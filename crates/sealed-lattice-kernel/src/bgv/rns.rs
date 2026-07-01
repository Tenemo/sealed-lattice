use crate::{
    bgv::parameters::{BgvBasisKind, POLYNOMIAL_DEGREE, bgv_parameters_hash},
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
    pub(crate) bgv_parameters_hash: String,
    pub(crate) basis_id: String,
    pub(crate) level: usize,
    pub(crate) coefficient_count: usize,
    pub(crate) domain: PolynomialDomain,
    pub(crate) moduli: Vec<u64>,
    pub(crate) residues_by_modulus: Vec<Vec<u64>>,
}

impl RnsPolynomial {
    pub(crate) fn coefficient_domain(
        basis_kind: BgvBasisKind,
        level: usize,
        bgv_parameters_hash: String,
        residues_by_modulus: Vec<Vec<u64>>,
    ) -> CanonicalResult<Self> {
        let moduli = basis_kind.moduli_for_level(level).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "requested BGV-RNS basis level is outside the selected parameters",
            )
        })?;
        let polynomial = Self {
            bgv_parameters_hash,
            basis_id: basis_kind.basis_id().to_string(),
            level,
            coefficient_count: POLYNOMIAL_DEGREE,
            domain: PolynomialDomain::Coefficient,
            moduli,
            residues_by_modulus,
        };
        polynomial.validate()?;

        Ok(polynomial)
    }

    pub(crate) fn validate(&self) -> CanonicalResult<()> {
        if self.bgv_parameters_hash != bgv_parameters_hash()? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "BGV-RNS object parameters hash does not match the selected BGV parameters",
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
                CanonicalErrorCode::ComponentMismatch,
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
                "protocol-path BGV-RNS objects must be coefficient-domain canonical objects",
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
    use crate::bgv::parameters::{
        BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE, SPECIAL_PRIME, bgv_parameters_hash,
    };

    #[test]
    fn coefficient_domain_object_validates_selected_basis() {
        let residues_by_modulus = vec![vec![0_u64; POLYNOMIAL_DEGREE]];
        let object = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            0,
            bgv_parameters_hash().expect("parameters hash"),
            residues_by_modulus,
        )
        .expect("object should validate");

        assert_eq!(object.domain, PolynomialDomain::Coefficient);
        assert_eq!(object.moduli.len(), 1);
    }

    #[test]
    fn rns_validation_binds_each_selected_basis_and_level() {
        let bgv_parameters_hash = bgv_parameters_hash().expect("parameters hash");
        let data = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            DATA_PRIMES.len() - 1,
            bgv_parameters_hash.clone(),
            DATA_PRIMES
                .iter()
                .map(|modulus| vec![modulus - 1; POLYNOMIAL_DEGREE])
                .collect(),
        )
        .expect("full data basis object");
        assert_eq!(data.moduli, DATA_PRIMES);

        let extended = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Extended,
            DATA_PRIMES.len(),
            bgv_parameters_hash.clone(),
            DATA_PRIMES
                .iter()
                .chain([SPECIAL_PRIME].iter())
                .map(|modulus| vec![modulus - 1; POLYNOMIAL_DEGREE])
                .collect(),
        )
        .expect("extended basis object");
        assert_eq!(extended.moduli.len(), DATA_PRIMES.len() + 1);

        let special = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Special,
            0,
            bgv_parameters_hash,
            vec![vec![SPECIAL_PRIME - 1; POLYNOMIAL_DEGREE]],
        )
        .expect("special basis object");
        assert_eq!(special.moduli, vec![SPECIAL_PRIME]);
    }

    #[test]
    fn rns_validation_rejects_ntt_domain_bad_residues_and_shape_drift() {
        let mut object = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            0,
            bgv_parameters_hash().expect("parameters hash"),
            vec![vec![0_u64; POLYNOMIAL_DEGREE]],
        )
        .expect("object should build");
        object.domain = PolynomialDomain::Ntt;
        assert!(object.validate().is_err());

        object.domain = PolynomialDomain::Coefficient;
        object.residues_by_modulus[0][0] = object.moduli[0];
        assert!(object.validate().is_err());

        let mut wrong_parameters = object.clone();
        wrong_parameters.residues_by_modulus[0][0] = 0;
        wrong_parameters.bgv_parameters_hash = "0".repeat(128);
        assert!(wrong_parameters.validate().is_err());

        let mut wrong_basis = object.clone();
        wrong_basis.residues_by_modulus[0][0] = 0;
        wrong_basis.basis_id = "not-a-selected-basis".to_string();
        assert!(wrong_basis.validate().is_err());

        let mut wrong_coefficient_count = object.clone();
        wrong_coefficient_count.residues_by_modulus[0][0] = 0;
        wrong_coefficient_count.coefficient_count = POLYNOMIAL_DEGREE - 1;
        assert!(wrong_coefficient_count.validate().is_err());

        let mut wrong_limb_count = object;
        wrong_limb_count
            .residues_by_modulus
            .push(vec![0_u64; POLYNOMIAL_DEGREE]);
        assert!(wrong_limb_count.validate().is_err());
    }
}
