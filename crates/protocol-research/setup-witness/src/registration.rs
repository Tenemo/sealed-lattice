use super::*;

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
        assert_eq!(width, 20);
        self.values = Some(values.to_vec());
    }
}

pub struct RegistrationKey {
    public: Vec<BigInt>,
    secret: Zeroizing<Vec<i8>>,
    proof_words: Option<Zeroizing<Vec<Vec<u16>>>>,
    #[cfg(feature = "custody")]
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
        let modulus = BigInt::from_bytes_le(Sign::Plus, &PARAMETERS[112..132]);
        let common = contribution::common_polynomial(42).unwrap();
        let mut witness = Witness::new();
        let mut secret = witness.sparse("registration-secret", DEGREE, 256, &plan);
        let mut output = KeyOutput { values: None };
        key(
            &mut witness,
            &mut output,
            &plan,
            KeyInput {
                label: "registration-key",
                common: &common,
                left: &secret,
                right: &secret.values,
                multiplier: BigInt::from(0),
                automorphism: 1,
                modulus: &modulus,
                limbs: 2,
                width: 20,
            },
        );
        assert_eq!(witness.words.len(), 3);
        assert_eq!(witness.booleans.len(), 2);
        let proof_words = Zeroizing::new(std::mem::take(&mut witness.words));
        Self {
            public: output.values.unwrap(),
            secret: Zeroizing::new(std::mem::take(&mut *secret.values)),
            proof_words: Some(proof_words),
            #[cfg(feature = "custody")]
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
        header: [u8; 198],
        encrypted_constant: Vec<BigInt>,
        encrypted_linear: Vec<BigInt>,
        target_linear: Vec<BigInt>,
    ) -> Result<linked_release_proof::PreparedRelease, Error> {
        self.validate_retained()?;
        let common = contribution::common_polynomial(42).map_err(|_| Error::InvalidState)?;
        let secret = Zeroizing::new(self.secret.iter().copied().map(i128::from).collect());
        let inputs = linked_release_proof::ReleaseInputs::new(
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
    pub fn validate_retained(&self) -> Result<(), Error> {
        let public_modulus = BigInt::from_bytes_le(Sign::Plus, &PARAMETERS[112..132]);
        let public_half = public_modulus >> 1usize;
        if self.secret.len() != DEGREE
            || self.public.len() != DEGREE
            || self.public.iter().any(|value| value.abs() > public_half)
            || self.secret.iter().filter(|value| **value == 1).count() != 128
            || self.secret.iter().filter(|value| **value == -1).count() != 128
            || self.secret.iter().any(|value| !(-1..=1).contains(value))
        {
            return Err(Error::InvalidState);
        }
        let plan = Plan::new(DEGREE);
        let transformed = Zeroizing::new(plan.sparse_transform(&self.secret));
        let common = contribution::common_polynomial(42).map_err(|_| Error::InvalidState)?;
        let products = Zeroizing::new(plan.digit_products(&common, &self.secret, &transformed, 2));
        let modulus = reduction::Modulus::from_bytes(&PARAMETERS[112..132])
            .map_err(|_| Error::InvalidState)?;
        for position in 0..DEGREE {
            let raw = Zeroizing::new([
                products[0][position] + digit(&self.public[position], 0),
                products[1][position] + digit(&self.public[position], 1),
            ]);
            let mut output = Zeroizing::new([0u128; 2]);
            let reduced = modulus
                .reduce(raw.as_ref(), output.as_mut())
                .map_err(|_| Error::InvalidState)?;
            if output[1] != 0 || output[0] > 64 || (!reduced.negative && output[0] == 64) {
                return Err(Error::InvalidState);
            }
        }
        Ok(())
    }
    pub fn take_proof_columns(&mut self) -> Result<Vec<Vec<u16>>, Error> {
        let mut words = self.proof_words.take().ok_or(Error::Consumed)?;
        let mut columns = std::mem::take(&mut *words);
        for sign in [1i8, -1] {
            columns.push(
                self.secret
                    .iter()
                    .map(|value| u16::from(*value == sign))
                    .collect(),
            );
        }
        Ok(columns)
    }
}

#[cfg(feature = "custody")]
#[path = "registration-custody.rs"]
mod custody;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_key_survives_proof_handoff_and_rejects_changed_secret_with_the_same_support() {
        let mut key = RegistrationKey::new();
        key.validate_retained().unwrap();
        let columns = key.take_proof_columns().unwrap();
        assert_eq!(columns.len(), 5);
        assert!(key.take_proof_columns().is_err());
        key.validate_retained().unwrap();
        let positive = key.secret.iter().position(|value| *value == 1).unwrap();
        let zero = key.secret.iter().position(|value| *value == 0).unwrap();
        key.secret.swap(positive, zero);
        assert!(key.validate_retained().is_err());
    }
}
