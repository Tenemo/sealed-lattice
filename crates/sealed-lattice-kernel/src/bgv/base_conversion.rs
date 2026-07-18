use crate::{
    bgv::{
        parameters::{BgvBasisKind, PLAINTEXT_MODULUS},
        rns::RnsPolynomial,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) fn lift_plaintext_coefficients_to_basis(
    coefficients: &[u64],
    target_basis_kind: BgvBasisKind,
    target_level: usize,
) -> CanonicalResult<RnsPolynomial> {
    if coefficients
        .iter()
        .any(|coefficient| *coefficient >= PLAINTEXT_MODULUS)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "plaintext coefficient is outside the selected plaintext field",
        ));
    }
    let moduli = target_basis_kind
        .moduli_for_level(target_level)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "target basis level is outside the selected parameters",
            )
        })?;
    let residues_by_modulus = moduli
        .iter()
        .map(|modulus| {
            coefficients
                .iter()
                .map(|coefficient| coefficient % modulus)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    RnsPolynomial::coefficient_domain(target_basis_kind, target_level, residues_by_modulus)
}

// "Plaintext-lifted" means the same canonical plaintext-field value is stored identically
// across every RNS limb at each coefficient, not a general CRT object. This
// rejects limbs that disagree and residues that are congruent modulo the
// plaintext modulus but are not the identical lifted value.
#[cfg(test)]
pub(crate) fn convert_plaintext_lifted_basis(
    source: &RnsPolynomial,
    target_basis_kind: BgvBasisKind,
    target_level: usize,
) -> CanonicalResult<RnsPolynomial> {
    source.validate()?;
    let first_limb = source.residues_by_modulus.first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "source basis has no residue limbs",
        )
    })?;
    let source_moduli = source
        .basis_kind
        .moduli_for_level(source.level)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "source basis level is outside the selected parameters",
            )
        })?;
    for (coefficient_index, first_limb_coefficient) in first_limb.iter().enumerate() {
        let field_value = *first_limb_coefficient;
        if field_value >= PLAINTEXT_MODULUS {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "source basis is not a canonical plaintext-lifted BGV-RNS object",
            ));
        }
        for (modulus_index, modulus) in source_moduli.iter().enumerate() {
            if source.residues_by_modulus[modulus_index][coefficient_index] != field_value {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "source basis is not a consistent plaintext-lifted BGV-RNS object",
                ));
            }
            if source.residues_by_modulus[modulus_index][coefficient_index] >= *modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "source basis contains a non-canonical residue",
                ));
            }
        }
    }

    lift_plaintext_coefficients_to_basis(
        &first_limb
            .iter()
            .map(|coefficient| coefficient % PLAINTEXT_MODULUS)
            .collect::<Vec<_>>(),
        target_basis_kind,
        target_level,
    )
}

#[cfg(test)]
mod tests {
    use super::{convert_plaintext_lifted_basis, lift_plaintext_coefficients_to_basis};
    use crate::bgv::parameters::{BgvBasisKind, PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE};

    #[test]
    fn base_conversion_lifts_plaintext_coefficients_to_selected_bases() {
        let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        coefficients[0] = PLAINTEXT_MODULUS - 1;
        coefficients[1] = 1;
        let source = lift_plaintext_coefficients_to_basis(&coefficients, BgvBasisKind::Data, 0)
            .expect("data basis object");
        let converted = convert_plaintext_lifted_basis(&source, BgvBasisKind::Extended, 1)
            .expect("extended basis conversion");

        assert_eq!(converted.residues_by_modulus.len(), 2);
        assert_eq!(converted.residues_by_modulus[0][0], PLAINTEXT_MODULUS - 1);
        assert_eq!(converted.residues_by_modulus[1][1], 1);
        // Every residue vector spans the full ring, and the unset coefficients
        // stay zero in both bases: a conversion that corrupted or shifted other
        // positions would still satisfy the two spot checks above.
        assert_eq!(converted.residues_by_modulus[0].len(), POLYNOMIAL_DEGREE);
        assert_eq!(converted.residues_by_modulus[1].len(), POLYNOMIAL_DEGREE);
        for coefficient_index in 2..POLYNOMIAL_DEGREE {
            assert_eq!(converted.residues_by_modulus[0][coefficient_index], 0);
            assert_eq!(converted.residues_by_modulus[1][coefficient_index], 0);
        }
    }

    #[test]
    fn base_conversion_rejects_inconsistent_plaintext_lift() {
        let coefficients = vec![7_u64; POLYNOMIAL_DEGREE];
        let mut source = lift_plaintext_coefficients_to_basis(&coefficients, BgvBasisKind::Data, 1)
            .expect("data basis object");
        source.residues_by_modulus[1][0] = 8;

        assert!(convert_plaintext_lifted_basis(&source, BgvBasisKind::Extended, 2).is_err());
    }

    #[test]
    fn base_conversion_rejects_congruent_but_non_lifted_residues() {
        let coefficients = vec![7_u64; POLYNOMIAL_DEGREE];
        let mut source = lift_plaintext_coefficients_to_basis(&coefficients, BgvBasisKind::Data, 1)
            .expect("data basis object");
        source.residues_by_modulus[1][0] = 7 + PLAINTEXT_MODULUS;

        assert!(convert_plaintext_lifted_basis(&source, BgvBasisKind::Extended, 2).is_err());
    }
}
