#[cfg(test)]
use crate::bgv::ntt::forward_negacyclic_ntt;
use crate::{
    bgv::{
        base_conversion::lift_plaintext_coefficients_to_basis,
        ntt::inverse_negacyclic_ntt,
        parameters::{BgvBasisKind, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE, bgv_parameters_hash},
        rns::RnsPolynomial,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) struct EncodedBatchPlaintext {
    pub(crate) slots: Vec<u64>,
    pub(crate) coefficients_mod_plaintext: Vec<u64>,
    pub(crate) polynomial: RnsPolynomial,
}

// Batch encoding: slots are the NTT/evaluation representation, coefficients are
// the polynomial. Encoding is the inverse NTT (slots -> coefficients), then the
// coefficients are lifted into the RNS data basis.
pub(crate) fn encode_batch_plaintext_slots(
    supplied_slots: &[u64],
    target_level: usize,
) -> CanonicalResult<EncodedBatchPlaintext> {
    if supplied_slots.len() > POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV batch encoder received more slots than the selected polynomial degree",
        ));
    }
    if supplied_slots.iter().any(|slot| *slot >= PLAINTEXT_MODULUS) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "BGV batch encoder slot value is outside GF(65537)",
        ));
    }
    let mut padded_slots = vec![0_u64; POLYNOMIAL_DEGREE];
    padded_slots[..supplied_slots.len()].copy_from_slice(supplied_slots);
    let coefficients_mod_plaintext = inverse_negacyclic_ntt(&padded_slots, PLAINTEXT_MODULUS)?;
    let polynomial = lift_plaintext_coefficients_to_basis(
        &coefficients_mod_plaintext,
        BgvBasisKind::Data,
        target_level,
        bgv_parameters_hash()?,
    )?;

    Ok(EncodedBatchPlaintext {
        slots: padded_slots,
        coefficients_mod_plaintext,
        polynomial,
    })
}

// Decoding is the inverse of encoding: recover the plaintext coefficients from
// any limb, then run the forward NTT (coefficients -> slots).
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
                    CanonicalErrorCode::InvalidFixture,
                    format!(
                        "BGV plaintext limb {limb_index} coefficient {coefficient_index} is not a consistent plaintext lift",
                    ),
                ));
            }
        }
    }

    forward_negacyclic_ntt(&coefficients_mod_plaintext, PLAINTEXT_MODULUS)
}

#[cfg(test)]
mod tests {
    use super::{decode_batch_plaintext_polynomial, encode_batch_plaintext_slots};
    use crate::bgv::parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE};

    #[test]
    fn batch_encoder_round_trips_boundary_slots() {
        let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
        slots[0] = 65_536;
        slots[1] = 1;
        slots[17] = 32_768;
        slots[POLYNOMIAL_DEGREE - 1] = 99;
        let encoded = encode_batch_plaintext_slots(&slots, 0).expect("encode");
        let decoded = decode_batch_plaintext_polynomial(&encoded.polynomial).expect("decode");

        assert_eq!(decoded, slots);
        assert_eq!(encoded.polynomial.moduli, vec![DATA_PRIMES[0]]);
    }

    #[test]
    fn batch_encoder_round_trips_all_zero_and_all_max_slots() {
        for slots in [
            vec![0_u64; POLYNOMIAL_DEGREE],
            vec![65_536_u64; POLYNOMIAL_DEGREE],
        ] {
            let encoded = encode_batch_plaintext_slots(&slots, 1).expect("encode");
            let decoded = decode_batch_plaintext_polynomial(&encoded.polynomial).expect("decode");

            assert_eq!(decoded, slots);
            assert_eq!(encoded.polynomial.moduli, DATA_PRIMES[..=1].to_vec());
        }
    }

    #[test]
    fn batch_encoder_rejects_bad_slot_values_and_levels() {
        assert!(encode_batch_plaintext_slots(&[65_537], 0).is_err());
        assert!(encode_batch_plaintext_slots(&vec![0_u64; POLYNOMIAL_DEGREE + 1], 0).is_err());
        assert!(encode_batch_plaintext_slots(&[0], DATA_PRIMES.len()).is_err());
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
}
