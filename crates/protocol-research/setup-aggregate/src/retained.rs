use crate::{
    CHUNK_BYTES, PolynomialAdder, contribution_family,
    verified::{AggregatePolynomial, Refusal, VerifiedSetupAggregate},
};
use num_bigint::BigInt;
use registration_credentials::identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN};
use supported_profile::Profile;

/// Immutable coefficients read from exactly one owning aggregate reference.
/// This value is public key material, not participant signing or release authority.
pub struct VerifiedAggregatePolynomial {
    inventory: [u8; 64],
    index: usize,
    coefficients: Vec<BigInt>,
}
/// Private-operation input recovered from an authenticated local reference.
/// This type cannot create a public setup or verification capability.
pub struct RetainedAggregatePolynomial {
    inventory: [u8; 64],
    index: usize,
    coefficients: Vec<BigInt>,
}
impl RetainedAggregatePolynomial {
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn coefficients(&self) -> &[BigInt] {
        &self.coefficients
    }
}

/// Parsed local references only. Their provenance is the owning setup verifier's
/// result, keyed to the participant's credential when retained; the consumer
/// checks that key before parsing, so an arbitrary copy supplies no premise.
pub struct RetainedSetupInputs {
    profile: Profile,
    inventory: [u8; 64],
    polynomials: Vec<AggregatePolynomial>,
}
impl RetainedSetupInputs {
    /// Encodes the reference from the owning verifier's result in the fixed
    /// contribution-polynomial order that `parse` consumes.
    pub fn reference(setup: &VerifiedSetupAggregate) -> Result<Vec<u8>, Refusal> {
        let mut bytes = Vec::from(b"SAV1".as_slice());
        bytes.extend(setup.inventory().identity());
        let indices = setup.profile().contribution_body_polynomials();
        if setup.polynomials().len() != indices.len() {
            return Err(Refusal::Incomplete);
        }
        for (index, polynomial) in indices.into_iter().zip(setup.polynomials()) {
            if polynomial.index() != index {
                return Err(Refusal::Order);
            }
            bytes.extend(polynomial.digest());
        }
        Ok(bytes)
    }
    /// The profile is the one of the setup that owns the expected inventory.
    pub fn parse(
        profile: Profile,
        bytes: &[u8],
        expected_inventory: [u8; 64],
    ) -> Result<Self, Refusal> {
        let indices = profile.contribution_body_polynomials();
        if bytes.len() != 4 + 64 + 64 * indices.len()
            || &bytes[..4] != b"SAV1"
            || bytes[4..68] != expected_inventory
        {
            return Err(Refusal::Context);
        }
        let polynomials = indices
            .into_iter()
            .zip(bytes[68..].chunks_exact(64))
            .map(|(index, digest)| AggregatePolynomial {
                index,
                bytes: profile.setup_polynomial_bytes(index).unwrap(),
                digest: digest.try_into().unwrap(),
            })
            .collect();
        Ok(Self {
            profile,
            inventory: expected_inventory,
            polynomials,
        })
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn profile(&self) -> Profile {
        self.profile
    }
    pub(crate) fn into_polynomials(self) -> Vec<AggregatePolynomial> {
        self.polynomials
    }
    pub fn read_polynomial(&self, index: usize) -> Result<RetainedPolynomialReader, Refusal> {
        let expected = self
            .polynomials
            .iter()
            .find(|value| value.index == index)
            .ok_or(Refusal::Order)?
            .clone();
        Ok(RetainedPolynomialReader {
            reader: AggregatePolynomialReader::new(self.profile, self.inventory, expected)?,
        })
    }
}
pub struct RetainedPolynomialReader {
    reader: AggregatePolynomialReader,
}
impl RetainedPolynomialReader {
    pub fn push(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Refusal> {
        self.reader.push(offset, bytes)
    }
    pub fn finish(self) -> Result<RetainedAggregatePolynomial, Refusal> {
        self.reader.finish_retained()
    }
}
impl VerifiedAggregatePolynomial {
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn coefficients(&self) -> &[BigInt] {
        &self.coefficients
    }
}

/// No coefficient access is available before the complete byte identity matches.
pub struct AggregatePolynomialReader {
    inventory: [u8; 64],
    expected: AggregatePolynomial,
    decoder: PolynomialAdder,
    hash: IdentityHasher,
    coefficients: Vec<BigInt>,
    offset: usize,
    failed: bool,
}
impl AggregatePolynomialReader {
    pub(crate) fn new(
        profile: Profile,
        inventory: [u8; 64],
        expected: AggregatePolynomial,
    ) -> Result<Self, Refusal> {
        let family = contribution_family(profile, expected.index()).ok_or(Refusal::Order)?;
        if profile.setup_polynomial_bytes(expected.index()) != Some(expected.bytes()) {
            return Err(Refusal::Context);
        }
        let hash = IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], expected.bytes())
            .map_err(|_| Refusal::Context)?;
        Ok(Self {
            inventory,
            expected,
            decoder: PolynomialAdder::new(profile, family),
            hash,
            coefficients: Vec::with_capacity(profile.family_degree(family)),
            offset: 0,
            failed: false,
        })
    }
    pub fn push(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Refusal> {
        if self.failed {
            return Err(Refusal::Order);
        }
        let result = (|| {
            let width = self.decoder.width;
            if offset != self.offset
                || bytes.is_empty()
                || bytes.len() > CHUNK_BYTES
                || !bytes.len().is_multiple_of(width)
                || bytes.len() > self.expected.bytes().saturating_sub(self.offset)
            {
                return Err(Refusal::Body);
            }
            for coefficient in bytes.chunks_exact(width) {
                self.coefficients.push(
                    self.decoder
                        .decode(coefficient)
                        .map_err(|_| Refusal::Body)?,
                );
            }
            self.hash.absorb(bytes).map_err(|_| Refusal::Body)?;
            self.offset += bytes.len();
            Ok(())
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    pub fn finish(self) -> Result<VerifiedAggregatePolynomial, Refusal> {
        let retained = self.finish_retained()?;
        Ok(VerifiedAggregatePolynomial {
            inventory: retained.inventory,
            index: retained.index,
            coefficients: retained.coefficients,
        })
    }
    fn finish_retained(self) -> Result<RetainedAggregatePolynomial, Refusal> {
        if self.failed || self.offset != self.expected.bytes() {
            return Err(Refusal::Incomplete);
        }
        let digest = self.hash.finish().map_err(|_| Refusal::PreviousAggregate)?;
        if &digest != self.expected.digest() {
            return Err(Refusal::PreviousAggregate);
        }
        Ok(RetainedAggregatePolynomial {
            inventory: self.inventory,
            index: self.expected.index(),
            coefficients: self.coefficients,
        })
    }
}

#[cfg(test)]
mod private_tests {
    use super::*;
    fn profile() -> Profile {
        Profile::new(3, 2).unwrap()
    }
    fn record() -> (Vec<u8>, Vec<u8>) {
        let profile = profile();
        let key = profile.auxiliary_key_polynomial();
        let values = vec![0; profile.setup_polynomial_bytes(key).unwrap()];
        let mut record = Vec::from(b"SAV1".as_slice());
        record.extend([9; 64]);
        for index in profile.contribution_body_polynomials() {
            record.extend(if index == key {
                registration_credentials::identity::identity(PUBLIC_POLYNOMIAL_DOMAIN, &values)
                    .unwrap()
            } else {
                [0; 64]
            });
        }
        (record, values)
    }
    #[test]
    fn retained_inputs_check_complete_identity_and_canonical_values() {
        let (record, values) = record();
        let key_index = profile().auxiliary_key_polynomial();
        let inputs = RetainedSetupInputs::parse(profile(), &record, [9; 64]).unwrap();
        let mut reader = inputs.read_polynomial(key_index).unwrap();
        reader.push(0, &values).unwrap();
        let key = reader.finish().unwrap();
        assert_eq!(key.inventory(), &[9; 64]);
        assert_eq!(key.index(), key_index);
        assert!(
            key.coefficients()
                .iter()
                .all(|value| value == &BigInt::from(0))
        );
        let mut changed = values.clone();
        changed[1] = 1;
        let mut reader = inputs.read_polynomial(key_index).unwrap();
        reader.push(0, &changed).unwrap();
        assert!(reader.finish().is_err());
        let mut reader = inputs.read_polynomial(key_index).unwrap();
        reader.push(0, &values[..values.len() - 6]).unwrap();
        assert!(reader.finish().is_err());
        let mut negative_zero = values.clone();
        negative_zero[0] = 1;
        let mut reader = inputs.read_polynomial(key_index).unwrap();
        assert!(reader.push(0, &negative_zero).is_err());
        assert!(reader.push(0, &values).is_err());
        assert!(reader.finish().is_err());
        assert!(inputs.read_polynomial(0).is_err());
    }
    #[test]
    fn retained_reference_parser_refuses_wrong_inventory_profile_or_framing() {
        let (mut record, _) = record();
        assert!(RetainedSetupInputs::parse(profile(), &record, [8; 64]).is_err());
        assert!(
            RetainedSetupInputs::parse(profile(), &record[..record.len() - 1], [9; 64]).is_err()
        );
        // A four-participant setup carries two more share encryptions.
        assert!(RetainedSetupInputs::parse(Profile::new(4, 2).unwrap(), &record, [9; 64]).is_err());
        record.push(0);
        assert!(RetainedSetupInputs::parse(profile(), &record, [9; 64]).is_err());
        record.pop();
        record[0] ^= 1;
        assert!(RetainedSetupInputs::parse(profile(), &record, [9; 64]).is_err());
    }
}
