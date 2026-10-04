//! Original private operands of the first FHE encryption-key coordinate.
//! The enrollment owner supplies and retains the source randomness; this
//! arithmetic object creates no registration or contribution authority.

use crate::{
    DEGREE, KeyInput, Plan, PolynomialOutput, Profile, Sparse, Witness, contribution,
    errors_from_reader, integer, key_with_error, sparse_values_from_reader,
};
use num_bigint::BigInt;
use sha3::digest::XofReader;
use supported_profile::{FHE_SECRET_SUPPORT, Family};
use zeroize::Zeroizing;

pub struct FheKeySource {
    profile: Profile,
    secret: Zeroizing<Vec<i8>>,
    error: Zeroizing<Vec<i128>>,
}

impl FheKeySource {
    /// Samples the original secret followed by the first encryption error.
    /// The reader must come from the enrollment owner's independently retained
    /// seed for this exact modulus and common-polynomial sampler width.
    pub fn from_reader(profile: Profile, random: &mut impl XofReader) -> Self {
        Self {
            profile,
            secret: Zeroizing::new(sparse_values_from_reader(
                DEGREE,
                FHE_SECRET_SUPPORT,
                random,
            )),
            error: Zeroizing::new(errors_from_reader(DEGREE, random)),
        }
    }

    fn matches_family(&self, modulus: &[u8], common_sample_bits: usize) -> bool {
        self.profile.ciphertext_modulus().to_bytes() == modulus
            && self.profile.fhe_common_sample_bits() == common_sample_bits
    }

    /// Emits only b[0], using the same common polynomial, integer lifting and
    /// canonical polynomial-output contract as contribution generation.
    pub fn public_coordinate(&self, output: &mut impl PolynomialOutput) {
        let profile = self.profile;
        let plan = Plan::new(DEGREE);
        let secret = Sparse {
            values: Zeroizing::new(self.secret.to_vec()),
            transform: Zeroizing::new(plan.sparse_transform(&self.secret)),
        };
        let common = contribution::common_polynomial(profile, profile.fhe_polynomial(0, 0))
            .expect("The first FHE common polynomial belongs to every checked profile.");
        let modulus = integer(&profile.family_modulus(Family::Fhe));
        let input = KeyInput {
            label: "encryption-0",
            common: &common,
            left: &secret,
            right: &secret.values,
            multiplier: BigInt::from(0),
            automorphism: 1,
            modulus: &modulus,
            limbs: profile.fhe_limbs(),
            width: profile.family_magnitude_bytes(Family::Fhe),
        };
        let products = input.products();
        key_with_error(&mut Witness::new(), output, input, products, &self.error);
    }

    pub(crate) fn check_profile(&self, profile: Profile) -> Result<(), contribution::Error> {
        if !self.matches_family(
            &profile.ciphertext_modulus().to_bytes(),
            profile.fhe_common_sample_bits(),
        ) {
            return Err(contribution::Error::SourceFamily);
        }
        Ok(())
    }

    pub(crate) fn into_parts(self) -> (Zeroizing<Vec<i8>>, Zeroizing<Vec<i128>>) {
        (self.secret, self.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{
        Shake256,
        digest::{ExtendableOutput, Update},
    };

    fn source(profile: Profile, seed: u8) -> FheKeySource {
        let mut hash = Shake256::default();
        hash.update(&[seed; 64]);
        FheKeySource::from_reader(profile, &mut hash.finalize_xof())
    }

    #[test]
    fn explicit_reader_reproduces_both_original_private_operands() {
        let profile = Profile::new(3, 2).unwrap();
        let first = source(profile, 7);
        let repeated = source(profile, 7);
        let different = source(profile, 11);
        assert!(first.secret == repeated.secret);
        assert!(first.error == repeated.error);
        assert!(first.secret != different.secret);
        assert!(first.error != different.error);
        assert_eq!(first.secret.len(), DEGREE);
        for sign in [-1, 1] {
            assert_eq!(
                first.secret.iter().filter(|value| **value == sign).count(),
                FHE_SECRET_SUPPORT / 2
            );
        }
        assert!(first.secret.iter().all(|value| (-1..=1).contains(value)));
        assert_eq!(first.error.len(), DEGREE);
        assert!(first.error.iter().all(|value| (-64..64).contains(value)));
    }

    #[test]
    fn wrong_modulus_or_common_sampler_width_refuses_before_continuation() {
        let profile = Profile::new(3, 2).unwrap();
        let original = source(profile, 7);
        let modulus = profile.ciphertext_modulus().to_bytes();
        assert!(original.matches_family(&modulus, profile.fhe_common_sample_bits()));
        assert!(!original.matches_family(&modulus, profile.fhe_common_sample_bits() + 8));
        let mut changed_modulus = modulus;
        changed_modulus[0] ^= 2;
        assert!(!original.matches_family(&changed_modulus, profile.fhe_common_sample_bits()));

        let other = Profile::all()
            .find(|candidate| candidate.ciphertext_modulus() != profile.ciphertext_modulus())
            .unwrap();
        assert!(matches!(
            contribution::Contribution::from_source(other, original),
            Err(contribution::Error::SourceFamily)
        ));
    }
}
