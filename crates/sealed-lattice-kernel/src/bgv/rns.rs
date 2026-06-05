use crate::{
    bgv::profile::{
        BgvBasisKind, POLYNOMIAL_DEGREE, encrypted_ballot_aggregate_layout_hash, profile_hash,
    },
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
    pub(crate) profile_hash: String,
    pub(crate) basis_id: String,
    pub(crate) level: usize,
    pub(crate) coefficient_count: usize,
    pub(crate) domain: PolynomialDomain,
    pub(crate) encrypted_ballot_aggregate_layout_hash: String,
    pub(crate) moduli: Vec<u64>,
    pub(crate) residues_by_modulus: Vec<Vec<u64>>,
}

impl RnsPolynomial {
    pub(crate) fn coefficient_domain(
        basis_kind: BgvBasisKind,
        level: usize,
        encrypted_ballot_aggregate_layout_hash: String,
        residues_by_modulus: Vec<Vec<u64>>,
    ) -> CanonicalResult<Self> {
        let moduli = basis_kind.moduli_for_level(level).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "requested BGV-RNS basis level is outside the selected profile",
            )
        })?;
        let polynomial = Self {
            profile_hash: profile_hash()?,
            basis_id: basis_kind.basis_id().to_string(),
            level,
            coefficient_count: POLYNOMIAL_DEGREE,
            domain: PolynomialDomain::Coefficient,
            encrypted_ballot_aggregate_layout_hash,
            moduli,
            residues_by_modulus,
        };
        polynomial.validate()?;

        Ok(polynomial)
    }

    pub(crate) fn validate(&self) -> CanonicalResult<()> {
        if self.profile_hash != profile_hash()? {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "BGV-RNS object profile hash does not match the selected profile",
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
        if self.encrypted_ballot_aggregate_layout_hash != encrypted_ballot_aggregate_layout_hash()?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "BGV-RNS object layout hash does not match the selected direct aggregate layout",
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
    use crate::bgv::profile::{
        BgvBasisKind, DATA_PRIMES, POLYNOMIAL_DEGREE, SPECIAL_PRIME,
        encrypted_ballot_aggregate_layout_hash,
    };

    #[test]
    fn coefficient_domain_object_validates_selected_basis() {
        let residues_by_modulus = vec![vec![0_u64; POLYNOMIAL_DEGREE]];
        let object = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            0,
            encrypted_ballot_aggregate_layout_hash().expect("layout hash"),
            residues_by_modulus,
        )
        .expect("object should validate");

        assert_eq!(object.domain, PolynomialDomain::Coefficient);
        assert_eq!(object.moduli.len(), 1);
    }

    #[test]
    fn rns_validation_binds_each_selected_basis_and_level() {
        let encrypted_ballot_aggregate_layout_hash =
            encrypted_ballot_aggregate_layout_hash().expect("layout hash");
        let data = RnsPolynomial::coefficient_domain(
            BgvBasisKind::Data,
            DATA_PRIMES.len() - 1,
            encrypted_ballot_aggregate_layout_hash.clone(),
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
            encrypted_ballot_aggregate_layout_hash.clone(),
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
            encrypted_ballot_aggregate_layout_hash,
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
            encrypted_ballot_aggregate_layout_hash().expect("layout hash"),
            vec![vec![0_u64; POLYNOMIAL_DEGREE]],
        )
        .expect("object should build");
        object.domain = PolynomialDomain::Ntt;
        assert!(object.validate().is_err());

        object.domain = PolynomialDomain::Coefficient;
        object.residues_by_modulus[0][0] = object.moduli[0];
        assert!(object.validate().is_err());

        let mut wrong_profile = object.clone();
        wrong_profile.residues_by_modulus[0][0] = 0;
        wrong_profile.profile_hash = "0".repeat(128);
        assert!(wrong_profile.validate().is_err());

        let mut wrong_basis = object.clone();
        wrong_basis.residues_by_modulus[0][0] = 0;
        wrong_basis.basis_id = "not-a-selected-basis".to_string();
        assert!(wrong_basis.validate().is_err());

        let mut wrong_coefficient_count = object.clone();
        wrong_coefficient_count.residues_by_modulus[0][0] = 0;
        wrong_coefficient_count.coefficient_count = POLYNOMIAL_DEGREE - 1;
        assert!(wrong_coefficient_count.validate().is_err());

        let mut wrong_layout = object.clone();
        wrong_layout.residues_by_modulus[0][0] = 0;
        wrong_layout.encrypted_ballot_aggregate_layout_hash = "0".repeat(128);
        assert!(wrong_layout.validate().is_err());

        let mut wrong_limb_count = object;
        wrong_limb_count
            .residues_by_modulus
            .push(vec![0_u64; POLYNOMIAL_DEGREE]);
        assert!(wrong_limb_count.validate().is_err());
    }
}
