use crate::{
    bgv::{
        profile::{BgvBasisKind, PLAINTEXT_MODULUS},
        rns::RnsPolynomial,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

pub(crate) fn lift_plaintext_coefficients_to_basis(
    coefficients: &[u64],
    target_basis_kind: BgvBasisKind,
    target_level: usize,
    layout_hash: String,
) -> CanonicalResult<RnsPolynomial> {
    if coefficients
        .iter()
        .any(|coefficient| *coefficient >= PLAINTEXT_MODULUS)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "plaintext coefficient is outside GF(65537)",
        ));
    }
    let moduli = target_basis_kind
        .moduli_for_level(target_level)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "target basis level is outside the selected profile",
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

    RnsPolynomial::coefficient_domain(
        target_basis_kind,
        target_level,
        layout_hash,
        residues_by_modulus,
    )
}

// "Plaintext-lifted" means the SAME field value (< 65537) is stored identically
// across every RNS limb at each coefficient, not a general CRT object. This
// rejects limbs that disagree, AND residues that are congruent mod 65537 but
// not the identical lifted value (e.g. 7 vs 7+65537).
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
    for (coefficient_index, first_limb_coefficient) in
        first_limb.iter().enumerate().take(source.coefficient_count)
    {
        let field_value = *first_limb_coefficient;
        if field_value >= PLAINTEXT_MODULUS {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "source basis is not a canonical plaintext-lifted BGV-RNS object",
            ));
        }
        for (modulus_index, modulus) in source.moduli.iter().enumerate() {
            if source.residues_by_modulus[modulus_index][coefficient_index] != field_value {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "source basis is not a consistent plaintext-lifted BGV-RNS object",
                ));
            }
            if source.residues_by_modulus[modulus_index][coefficient_index] >= *modulus {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
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
        source.layout_hash.clone(),
    )
}

#[cfg(test)]
mod tests {
    use super::{convert_plaintext_lifted_basis, lift_plaintext_coefficients_to_basis};
    use crate::bgv::profile::{BgvBasisKind, POLYNOMIAL_DEGREE, layout_hash};

    #[test]
    fn base_conversion_lifts_plaintext_coefficients_to_selected_bases() {
        let mut coefficients = vec![0_u64; POLYNOMIAL_DEGREE];
        coefficients[0] = 65_536;
        coefficients[1] = 1;
        let layout_hash = layout_hash().expect("layout hash");
        let source =
            lift_plaintext_coefficients_to_basis(&coefficients, BgvBasisKind::Data, 0, layout_hash)
                .expect("data basis object");
        let converted = convert_plaintext_lifted_basis(&source, BgvBasisKind::Extended, 1)
            .expect("extended basis conversion");

        assert_eq!(converted.moduli.len(), 2);
        assert_eq!(converted.residues_by_modulus[0][0], 65_536);
        assert_eq!(converted.residues_by_modulus[1][1], 1);
    }

    #[test]
    fn base_conversion_rejects_inconsistent_plaintext_lift() {
        let coefficients = vec![7_u64; POLYNOMIAL_DEGREE];
        let mut source = lift_plaintext_coefficients_to_basis(
            &coefficients,
            BgvBasisKind::Data,
            1,
            layout_hash().expect("layout hash"),
        )
        .expect("data basis object");
        source.residues_by_modulus[1][0] = 8;

        assert!(convert_plaintext_lifted_basis(&source, BgvBasisKind::Extended, 2).is_err());
    }

    #[test]
    fn base_conversion_rejects_congruent_but_non_lifted_residues() {
        let coefficients = vec![7_u64; POLYNOMIAL_DEGREE];
        let mut source = lift_plaintext_coefficients_to_basis(
            &coefficients,
            BgvBasisKind::Data,
            1,
            layout_hash().expect("layout hash"),
        )
        .expect("data basis object");
        source.residues_by_modulus[1][0] = 7 + 65_537;

        assert!(convert_plaintext_lifted_basis(&source, BgvBasisKind::Extended, 2).is_err());
    }
}
