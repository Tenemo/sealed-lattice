use crate::{
    bgv::{
        evaluator::engine::Ciphertext,
        parameters::{DATA_PRIMES, PLAINTEXT_MODULUS},
        serialization::parse_two_component_data_ciphertext_at_level,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::FOUNDATION_PROFILE,
};

/// Decodes one descriptor-authenticated evaluator target using metadata
/// recomputed by the exact selected evaluator-program verifier. The canonical
/// ciphertext encoding intentionally carries neither the semantic output level
/// nor the decryption scaling as a self-attested field.
pub(crate) fn decode_verified_target_ciphertext(
    canonical_bytes: &[u8],
    verified_target_level: usize,
    verified_decrypt_scaling: u64,
) -> CanonicalResult<Ciphertext> {
    if canonical_bytes.is_empty()
        || canonical_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "finalized BGV target exceeds the copied-buffer safety bound",
        ));
    }
    if verified_target_level >= DATA_PRIMES.len()
        || verified_decrypt_scaling == 0
        || verified_decrypt_scaling >= PLAINTEXT_MODULUS
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "verified BGV target metadata is outside the selected suite",
        ));
    }
    let parsed =
        parse_two_component_data_ciphertext_at_level(canonical_bytes, verified_target_level)?;
    Ok(Ciphertext {
        components: parsed
            .components
            .into_iter()
            .map(|component| component.residues_by_modulus)
            .collect(),
        level: verified_target_level,
        decrypt_scaling: verified_decrypt_scaling,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::{
        evaluator::top_k::CANONICAL_TARGET_CIPHERTEXT_LEVEL,
        parameters::{BgvBasisKind, POLYNOMIAL_DEGREE},
        rns::RnsPolynomial,
        serialization::{BgvObjectKind, serialize_bgv_object},
    };

    fn polynomial(level: usize, residue_offset: u64) -> RnsPolynomial {
        RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            level,
            DATA_PRIMES
                .iter()
                .take(level + 1)
                .enumerate()
                .map(|(limb_index, modulus)| {
                    (0..POLYNOMIAL_DEGREE)
                        .map(|coefficient_index| {
                            (residue_offset
                                + u64::try_from(limb_index).expect("limb index")
                                + u64::try_from(coefficient_index).expect("coefficient index"))
                                % modulus
                        })
                        .collect()
                })
                .collect(),
        )
        .expect("test polynomial")
    }

    #[test]
    fn selected_target_decoder_round_trips_exact_two_component_data_ciphertext() {
        let canonical_bytes = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[
                polynomial(CANONICAL_TARGET_CIPHERTEXT_LEVEL, 3),
                polynomial(CANONICAL_TARGET_CIPHERTEXT_LEVEL, 7),
            ],
        )
        .expect("canonical target");

        let decoded = decode_verified_target_ciphertext(
            &canonical_bytes,
            CANONICAL_TARGET_CIPHERTEXT_LEVEL,
            7,
        )
        .expect("target decodes");

        assert_eq!(decoded.level, CANONICAL_TARGET_CIPHERTEXT_LEVEL);
        assert_eq!(decoded.decrypt_scaling, 7);
        assert_eq!(decoded.components.len(), 2);
        assert_eq!(
            decoded.components[1][CANONICAL_TARGET_CIPHERTEXT_LEVEL][POLYNOMIAL_DEGREE - 1],
            (7 + u64::try_from(CANONICAL_TARGET_CIPHERTEXT_LEVEL).expect("level")
                + u64::try_from(POLYNOMIAL_DEGREE - 1).expect("degree"))
                % DATA_PRIMES[CANONICAL_TARGET_CIPHERTEXT_LEVEL]
        );
    }

    #[test]
    fn selected_target_decoder_rejects_wrong_level_component_count_and_trailing_bytes() {
        let wrong_level = if CANONICAL_TARGET_CIPHERTEXT_LEVEL == 0 {
            1
        } else {
            CANONICAL_TARGET_CIPHERTEXT_LEVEL - 1
        };
        let wrong_level_bytes = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[polynomial(wrong_level, 1), polynomial(wrong_level, 2)],
        )
        .expect("wrong-level object still serializes");
        assert!(
            decode_verified_target_ciphertext(
                &wrong_level_bytes,
                CANONICAL_TARGET_CIPHERTEXT_LEVEL,
                1,
            )
            .is_err()
        );

        let three_component_bytes = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[
                polynomial(CANONICAL_TARGET_CIPHERTEXT_LEVEL, 1),
                polynomial(CANONICAL_TARGET_CIPHERTEXT_LEVEL, 2),
                polynomial(CANONICAL_TARGET_CIPHERTEXT_LEVEL, 3),
            ],
        )
        .expect("three-component ciphertext");
        assert!(
            decode_verified_target_ciphertext(
                &three_component_bytes,
                CANONICAL_TARGET_CIPHERTEXT_LEVEL,
                1,
            )
            .is_err()
        );

        let mut trailing = serialize_bgv_object(
            BgvObjectKind::Ciphertext,
            &[
                polynomial(CANONICAL_TARGET_CIPHERTEXT_LEVEL, 4),
                polynomial(CANONICAL_TARGET_CIPHERTEXT_LEVEL, 5),
            ],
        )
        .expect("canonical target");
        trailing.push(0);
        assert!(
            decode_verified_target_ciphertext(&trailing, CANONICAL_TARGET_CIPHERTEXT_LEVEL, 1,)
                .is_err()
        );

        assert!(
            decode_verified_target_ciphertext(
                &trailing[..trailing.len() - 1],
                DATA_PRIMES.len(),
                1,
            )
            .is_err()
        );
        assert!(
            decode_verified_target_ciphertext(
                &trailing[..trailing.len() - 1],
                CANONICAL_TARGET_CIPHERTEXT_LEVEL,
                0,
            )
            .is_err()
        );
    }
}
