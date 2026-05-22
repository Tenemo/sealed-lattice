use crate::{
    bgv::profile::{BgvBasisKind, POLYNOMIAL_DEGREE, profile_digest},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolynomialDomain {
    Coefficient,
    Ntt,
}

impl PolynomialDomain {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Coefficient => "coefficient",
            Self::Ntt => "ntt",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "coefficient" => Some(Self::Coefficient),
            "ntt" => Some(Self::Ntt),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RnsPolynomial {
    pub(crate) profile_digest: String,
    pub(crate) basis_id: String,
    pub(crate) level: usize,
    pub(crate) coefficient_count: usize,
    pub(crate) domain: PolynomialDomain,
    pub(crate) layout_digest: String,
    pub(crate) moduli: Vec<u64>,
    pub(crate) residues_by_modulus: Vec<Vec<u64>>,
}

impl RnsPolynomial {
    pub(crate) fn coefficient_domain(
        basis_kind: BgvBasisKind,
        level: usize,
        layout_digest: String,
        residues_by_modulus: Vec<Vec<u64>>,
    ) -> CanonicalResult<Self> {
        let moduli = basis_kind.moduli_for_level(level).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "requested BGV-RNS basis level is outside the selected profile",
            )
        })?;
        let polynomial = Self {
            profile_digest: profile_digest()?,
            basis_id: basis_kind.basis_id().to_string(),
            level,
            coefficient_count: POLYNOMIAL_DEGREE,
            domain: PolynomialDomain::Coefficient,
            layout_digest,
            moduli,
            residues_by_modulus,
        };
        polynomial.validate()?;

        Ok(polynomial)
    }

    pub(crate) fn validate(&self) -> CanonicalResult<()> {
        if self.profile_digest != profile_digest()? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "BGV-RNS object profile digest does not match the selected profile",
            ));
        }
        let basis_kind = BgvBasisKind::from_basis_id(&self.basis_id).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "BGV-RNS basis identifier is not selected",
            )
        })?;
        let expected_moduli = basis_kind.moduli_for_level(self.level).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "BGV-RNS object level is outside the selected basis",
            )
        })?;
        if self.moduli != expected_moduli {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "BGV-RNS object modulus list does not match its selected basis and level",
            ));
        }
        if self.coefficient_count != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "BGV-RNS object coefficient count must match the selected polynomial degree",
            ));
        }
        if self.domain != PolynomialDomain::Coefficient {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "claim-path BGV-RNS objects must be coefficient-domain canonical objects",
            ));
        }
        if self.residues_by_modulus.len() != self.moduli.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "BGV-RNS object has the wrong number of residue limbs",
            ));
        }
        for (modulus_index, residues) in self.residues_by_modulus.iter().enumerate() {
            if residues.len() != self.coefficient_count {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "BGV-RNS residue limb has the wrong coefficient count",
                ));
            }
            let modulus = self.moduli[modulus_index];
            if residues.iter().any(|residue| *residue >= modulus) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "BGV-RNS residue limb contains a non-canonical residue",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{PolynomialDomain, RnsPolynomial};
    use crate::bgv::profile::{BgvBasisKind, POLYNOMIAL_DEGREE, layout_digest};

    #[test]
    fn coefficient_domain_object_validates_selected_basis() {
        let residues_by_modulus = vec![vec![0_u64; POLYNOMIAL_DEGREE]];
        let object = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            0,
            layout_digest().expect("layout digest"),
            residues_by_modulus,
        )
        .expect("object should validate");

        assert_eq!(object.domain, PolynomialDomain::Coefficient);
        assert_eq!(object.moduli.len(), 1);
    }

    #[test]
    fn rns_validation_rejects_ntt_domain_and_bad_residues() {
        let mut object = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            0,
            layout_digest().expect("layout digest"),
            vec![vec![0_u64; POLYNOMIAL_DEGREE]],
        )
        .expect("object should build");
        object.domain = PolynomialDomain::Ntt;
        assert!(object.validate().is_err());

        object.domain = PolynomialDomain::Coefficient;
        object.residues_by_modulus[0][0] = object.moduli[0];
        assert!(object.validate().is_err());
    }
}
