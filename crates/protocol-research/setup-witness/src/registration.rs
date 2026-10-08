use super::*;
use supported_profile::{RECIPIENT_SECRET_SUPPORT, relation::RELEASE_HEADER_BYTES, share_modulus};

#[derive(Debug)]
pub enum Error {
    Consumed,
    InvalidState,
}
struct KeyOutput {
    values: Option<Vec<BigInt>>,
}
impl PolynomialOutput for KeyOutput {
    fn polynomial(&mut self, values: &[BigInt], _modulus: &BigInt, width: usize) {
        assert!(self.values.is_none());
        assert_eq!(width, share_modulus().len());
        self.values = Some(values.to_vec());
    }
}

pub struct RegistrationKey {
    public: Vec<BigInt>,
    secret: Zeroizing<Vec<i8>>,
    sealed: bool,
}
impl Default for RegistrationKey {
    fn default() -> Self {
        Self::new()
    }
}
impl RegistrationKey {
    pub fn new() -> Self {
        let plan = Plan::new(DEGREE);
        let modulus = integer(share_modulus());
        let common = contribution::common_share_polynomial();
        let mut witness = Witness::new();
        let mut secret = witness.sparse(
            "registration-secret",
            DEGREE,
            RECIPIENT_SECRET_SUPPORT,
            &plan,
        );
        let mut output = KeyOutput { values: None };
        let input = KeyInput {
            label: "registration-key",
            common: &common,
            left: &secret,
            right: &secret.values,
            multiplier: BigInt::from(0),
            automorphism: 1,
            modulus: &modulus,
            limbs: 2,
            width: share_modulus().len(),
        };
        let products = input.products();
        key(&mut witness, &mut output, input, products);
        Self {
            public: output.values.unwrap(),
            secret: Zeroizing::new(std::mem::take(&mut *secret.values)),
            sealed: false,
        }
    }
    pub fn public_key(&self) -> &[BigInt] {
        &self.public
    }
    /// Internal prover input preparation. Application-facing release is gated
    /// by the enrollment layer's verified certificate and durable action root;
    /// the private key is never exported through the worker interface.
    pub fn prepare_release(
        &self,
        profile: Profile,
        header: [u8; RELEASE_HEADER_BYTES],
        encrypted_constant: Vec<BigInt>,
        encrypted_linear: Vec<BigInt>,
        target_linear: Vec<BigInt>,
    ) -> Result<linked_release_proof::PreparedRelease, Error> {
        let common = contribution::common_share_polynomial();
        let secret = Zeroizing::new(self.secret.iter().copied().map(i128::from).collect());
        let inputs = linked_release_proof::ReleaseInputs::new(
            profile,
            common,
            self.public.clone(),
            encrypted_constant,
            encrypted_linear,
            target_linear,
            secret,
        )
        .map_err(|_| Error::InvalidState)?;
        linked_release_proof::derive_bound(inputs, header).map_err(|_| Error::InvalidState)
    }
    fn validate_retained(&self) -> Result<(), Error> {
        let public_modulus = integer(share_modulus());
        let public_half = public_modulus >> 1usize;
        if self.secret.len() != DEGREE
            || self.public.len() != DEGREE
            || self.public.iter().any(|value| value.abs() > public_half)
            || self.secret.iter().filter(|value| **value == 1).count()
                != RECIPIENT_SECRET_SUPPORT / 2
            || self.secret.iter().filter(|value| **value == -1).count()
                != RECIPIENT_SECRET_SUPPORT / 2
            || self.secret.iter().any(|value| !(-1..=1).contains(value))
        {
            return Err(Error::InvalidState);
        }
        let plan = Plan::new(DEGREE);
        let transformed = Zeroizing::new(plan.sparse_transform(&self.secret));
        let common = contribution::common_share_polynomial();
        let products =
            Zeroizing::new(plan.digit_products(&common, &self.secret, &transformed, 2, RADIX_BITS));
        let modulus =
            reduction::Modulus::new(share_modulus(), RADIX_BITS).ok_or(Error::InvalidState)?;
        for position in 0..DEGREE {
            let raw = Zeroizing::new([
                products[0][position] + digit(&self.public[position], 0),
                products[1][position] + digit(&self.public[position], 1),
            ]);
            let mut output = Zeroizing::new([0u128; 2]);
            let reduced = modulus
                .reduce(raw.as_ref(), output.as_mut())
                .ok_or(Error::InvalidState)?;
            if output[1] != 0 || output[0] > 64 || (!reduced.negative && output[0] == 64) {
                return Err(Error::InvalidState);
            }
        }
        Ok(())
    }
    pub fn public_key_bytes(&self) -> Vec<u8> {
        let width = share_modulus().len();
        let mut bytes = Vec::with_capacity(DEGREE * (1 + width));
        for value in &self.public {
            let (sign, magnitude) = value.to_bytes_le();
            bytes.push(u8::from(sign == Sign::Minus));
            bytes.extend(&magnitude);
            bytes.resize(bytes.len() + width - magnitude.len(), 0);
        }
        bytes
    }
}

#[path = "registration-custody.rs"]
mod custody;
/// A sealed registration key: its magic, its secret's support positions and
/// the AES-GCM tag.
pub use custody::SEALED_BYTES as SEALED_KEY_BYTES;

#[cfg(test)]
#[path = "registration-tests.rs"]
mod tests;
