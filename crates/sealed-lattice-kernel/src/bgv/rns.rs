use crate::{
    bgv::parameters::{BgvBasisKind, POLYNOMIAL_DEGREE},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RnsPolynomial {
    pub(crate) basis_kind: BgvBasisKind,
    pub(crate) level: usize,
    pub(crate) residues_by_modulus: Vec<Vec<u64>>,
}

impl RnsPolynomial {
    pub(crate) fn coefficient_domain(
        basis_kind: BgvBasisKind,
        level: usize,
        residues_by_modulus: Vec<Vec<u64>>,
    ) -> CanonicalResult<Self> {
        basis_kind.moduli_for_level(level).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "requested BGV-RNS basis level is outside the selected parameters",
            )
        })?;
        let polynomial = Self {
            basis_kind,
            level,
            residues_by_modulus,
        };
        polynomial.validate()?;

        Ok(polynomial)
    }

    pub(crate) fn validate(&self) -> CanonicalResult<()> {
        let expected_moduli = self
            .basis_kind
            .moduli_for_level(self.level)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "BGV-RNS object level is outside the selected basis",
                )
            })?;
        if self.residues_by_modulus.len() != expected_moduli.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "BGV-RNS object has the wrong number of residue limbs",
            ));
        }
        for (modulus_index, residues) in self.residues_by_modulus.iter().enumerate() {
            if residues.len() != POLYNOMIAL_DEGREE {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "BGV-RNS residue limb has the wrong coefficient count",
                ));
            }
            let modulus = expected_moduli[modulus_index];
            if residues.iter().any(|residue| *residue >= modulus) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "BGV-RNS residue limb contains a non-canonical residue",
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RnsPolynomial;
    use crate::bgv::parameters::{BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE, SPECIAL_PRIMES};

    #[test]
    fn coefficient_domain_object_validates_selected_basis() {
        let residues_by_modulus = vec![vec![0_u64; POLYNOMIAL_DEGREE]];
        let object = RnsPolynomial::coefficient_domain(BgvBasisKind::Data, 0, residues_by_modulus)
            .expect("object should validate");

        assert_eq!(object.basis_kind, BgvBasisKind::Data);
        assert_eq!(object.residues_by_modulus.len(), 1);
    }

    #[test]
    fn rns_validation_binds_each_selected_basis_and_level() {
        let data = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            DATA_PRIMES.len() - 1,
            DATA_PRIMES
                .iter()
                .map(|modulus| vec![modulus - 1; POLYNOMIAL_DEGREE])
                .collect(),
        )
        .expect("full data basis object");
        assert_eq!(data.residues_by_modulus.len(), DATA_PRIMES.len());

        let extended = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Extended,
            DATA_PRIMES.len() + SPECIAL_PRIMES.len() - 1,
            DATA_PRIMES
                .iter()
                .chain(SPECIAL_PRIMES.iter())
                .map(|modulus| vec![modulus - 1; POLYNOMIAL_DEGREE])
                .collect(),
        )
        .expect("extended basis object");
        assert_eq!(
            extended.residues_by_modulus.len(),
            DATA_PRIMES.len() + SPECIAL_PRIMES.len()
        );

        let special = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Special,
            SPECIAL_PRIMES.len() - 1,
            SPECIAL_PRIMES
                .iter()
                .map(|modulus| vec![modulus - 1; POLYNOMIAL_DEGREE])
                .collect(),
        )
        .expect("special basis object");
        assert_eq!(special.residues_by_modulus.len(), SPECIAL_PRIMES.len());
    }

    #[test]
    fn rns_validation_rejects_bad_residues_and_shape_drift() {
        let mut object = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            0,
            vec![vec![0_u64; POLYNOMIAL_DEGREE]],
        )
        .expect("object should build");
        object.residues_by_modulus[0][0] = DATA_PRIMES[0];
        assert!(object.validate().is_err());

        let mut unsupported_special_level = object.clone();
        unsupported_special_level.residues_by_modulus[0][0] = 0;
        unsupported_special_level.basis_kind = BgvBasisKind::Special;
        unsupported_special_level.level = 1;
        assert!(unsupported_special_level.validate().is_err());

        let mut wrong_coefficient_count = object.clone();
        wrong_coefficient_count.residues_by_modulus[0][0] = 0;
        wrong_coefficient_count.residues_by_modulus[0].pop();
        assert!(wrong_coefficient_count.validate().is_err());

        let mut wrong_limb_count = object;
        wrong_limb_count
            .residues_by_modulus
            .push(vec![0_u64; POLYNOMIAL_DEGREE]);
        assert!(wrong_limb_count.validate().is_err());
    }
}
