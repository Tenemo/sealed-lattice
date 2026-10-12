use crate::{
    CHUNK_BYTES, PolynomialAdder, contribution_family,
    verified::{AggregatePolynomial, Refusal, VerifiedSetupAggregate},
};
use num_bigint::BigInt;
use protocol_foundations::identity::{IdentityHasher, PUBLIC_POLYNOMIAL_DOMAIN};
use supported_profile::Profile;

/// Immutable coefficients read from exactly one owning aggregate reference.
/// This value is public key material, not participant signing or release authority.
pub struct VerifiedAggregatePolynomial {
    setup_identity: [u8; 64],
    index: usize,
    coefficients: Vec<BigInt>,
}
/// Private-operation input recovered from an authenticated local reference.
/// This type cannot create a public setup or verification capability.
pub struct RetainedAggregatePolynomial {
    setup_identity: [u8; 64],
    index: usize,
    coefficients: Vec<BigInt>,
}
impl RetainedAggregatePolynomial {
    pub fn setup_identity(&self) -> &[u8; 64] {
        &self.setup_identity
    }
    pub fn index(&self) -> usize {
        self.index
    }
    pub fn coefficients(&self) -> &[BigInt] {
        &self.coefficients
    }
    pub fn into_coefficients(self) -> Vec<BigInt> {
        self.coefficients
    }
}

/// Parsed local references only. Their provenance is the owning setup verifier's
/// result, keyed to the participant's credential when retained; the consumer
/// checks that key before parsing, so an arbitrary copy supplies no premise.
pub struct RetainedSetupInputs {
    profile: Profile,
    setup_identity: [u8; 64],
    polynomials: Vec<AggregatePolynomial>,
}
pub(crate) fn encode_reference(
    magic: &[u8; 4],
    profile: Profile,
    identity: [u8; 64],
    polynomials: &[AggregatePolynomial],
) -> Result<Vec<u8>, Refusal> {
    let mut bytes = magic.to_vec();
    bytes.extend(identity);
    let indices = profile.contribution_body_polynomials();
    if polynomials.len() != indices.len() {
        return Err(Refusal::Incomplete);
    }
    for (index, polynomial) in indices.into_iter().zip(polynomials) {
        if polynomial.index() != index
            || Some(polynomial.bytes()) != profile.setup_polynomial_bytes(index)
        {
            return Err(Refusal::Order);
        }
        bytes.extend(polynomial.digest());
    }
    Ok(bytes)
}
impl RetainedSetupInputs {
    /// Encodes the reference from the owning verifier's result in the fixed
    /// contribution-polynomial order that `parse` consumes.
    pub fn reference(setup: &VerifiedSetupAggregate) -> Result<Vec<u8>, Refusal> {
        encode_reference(
            b"SAV1",
            setup.profile(),
            setup.identity(),
            setup.polynomials(),
        )
    }
    /// The profile is the one of the setup that owns the expected setup identity.
    pub fn parse(
        profile: Profile,
        bytes: &[u8],
        expected_setup_identity: [u8; 64],
    ) -> Result<Self, Refusal> {
        Self::parse_with_magic(b"SAV1", profile, bytes, expected_setup_identity)
    }
    pub(crate) fn parse_with_magic(
        magic: &[u8; 4],
        profile: Profile,
        bytes: &[u8],
        expected_setup_identity: [u8; 64],
    ) -> Result<Self, Refusal> {
        let indices = profile.contribution_body_polynomials();
        if bytes.len() != 4 + 64 + 64 * indices.len()
            || &bytes[..4] != magic
            || bytes[4..68] != expected_setup_identity
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
            setup_identity: expected_setup_identity,
            polynomials,
        })
    }
    pub fn setup_identity(&self) -> &[u8; 64] {
        &self.setup_identity
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
            reader: AggregatePolynomialReader::new(self.profile, self.setup_identity, expected)?,
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
    pub fn setup_identity(&self) -> &[u8; 64] {
        &self.setup_identity
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
    setup_identity: [u8; 64],
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
        setup_identity: [u8; 64],
        expected: AggregatePolynomial,
    ) -> Result<Self, Refusal> {
        let family = contribution_family(profile, expected.index()).ok_or(Refusal::Order)?;
        if profile.setup_polynomial_bytes(expected.index()) != Some(expected.bytes()) {
            return Err(Refusal::Context);
        }
        let hash = IdentityHasher::new(PUBLIC_POLYNOMIAL_DOMAIN, &[], expected.bytes())
            .map_err(|_| Refusal::Context)?;
        Ok(Self {
            setup_identity,
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
            setup_identity: retained.setup_identity,
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
            setup_identity: self.setup_identity,
            index: self.expected.index(),
            coefficients: self.coefficients,
        })
    }
}

#[cfg(test)]
#[path = "retained-private-tests.rs"]
mod private_tests;
