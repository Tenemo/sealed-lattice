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

    /// Encrypts these original operands before any contribution is generated.
    /// The registration owner supplies its independently retained encryption stream.
    pub fn encrypt(
        self,
        random: &mut impl XofReader,
    ) -> Result<crate::encrypted_source::EncryptedSource, crate::encrypted_source::Refusal> {
        let (public, witness) =
            crate::encrypted_source::generate(&self.secret, &self.error, random)?;
        Ok(crate::encrypted_source::EncryptedSource::new(
            self, public, witness,
        ))
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

    pub(crate) fn check_profile(&self, profile: Profile) -> Result<(), contribution::Refusal> {
        if !self.profile.same_fhe_key_family(profile) {
            return Err(contribution::Refusal::SourceFamily);
        }
        Ok(())
    }

    pub(crate) fn into_parts(self) -> (Zeroizing<Vec<i8>>, Zeroizing<Vec<i128>>) {
        (self.secret, self.error)
    }
}

#[cfg(test)]
#[path = "fhe-key-source-tests.rs"]
mod tests;
