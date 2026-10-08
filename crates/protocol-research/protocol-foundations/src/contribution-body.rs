use crate::{Error, identity::IdentityHasher, source_binding::SOURCE_SALT_BYTES};
use std::ops::RangeInclusive;
use supported_profile::{
    Profile,
    relation::{PROOF_HEADER_BYTES, setup_relation},
};

pub const BODY_HEADER_BYTES: usize = 4 + 8 + SOURCE_SALT_BYTES;
pub const BODY_DOMAIN: &str = "sealed-lattice/contribution-body/v1";
pub struct ContributionBodyHeader {
    pub proof_length: usize,
    pub source_salt: [u8; SOURCE_SALT_BYTES],
}
impl ContributionBodyHeader {
    pub fn decode(profile: Profile, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != BODY_HEADER_BYTES || &bytes[..4] != b"SCB2" {
            return Err(Error::Shape);
        }
        let proof_length = usize::try_from(u64::from_le_bytes(bytes[4..12].try_into().unwrap()))
            .map_err(|_| Error::Shape)?;
        if !proof_lengths(profile).contains(&proof_length) {
            return Err(Error::Shape);
        }
        Ok(Self {
            proof_length,
            source_salt: bytes[12..].try_into().unwrap(),
        })
    }
}
pub fn proof_lengths(profile: Profile) -> RangeInclusive<usize> {
    PROOF_HEADER_BYTES..=setup_relation(profile).maximum_proof_bytes()
}
pub fn body_lengths(profile: Profile) -> RangeInclusive<usize> {
    let fixed = BODY_HEADER_BYTES
        + profile
            .contribution_body_polynomials()
            .iter()
            .map(|index| profile.setup_polynomial_bytes(*index).unwrap())
            .sum::<usize>();
    let proof = proof_lengths(profile);
    fixed + proof.start()..=fixed + proof.end()
}
pub fn body_length(profile: Profile, proof_length: usize) -> Result<usize, Error> {
    if !proof_lengths(profile).contains(&proof_length) {
        return Err(Error::Shape);
    }
    Ok(BODY_HEADER_BYTES
        + profile
            .contribution_body_polynomials()
            .iter()
            .map(|index| profile.setup_polynomial_bytes(*index).unwrap())
            .sum::<usize>()
        + proof_length)
}
pub fn body_header(
    profile: Profile,
    proof_length: usize,
    source_salt: &[u8; SOURCE_SALT_BYTES],
) -> Result<[u8; BODY_HEADER_BYTES], Error> {
    if !proof_lengths(profile).contains(&proof_length) {
        return Err(Error::Shape);
    }
    let mut header = [0; BODY_HEADER_BYTES];
    header[..4].copy_from_slice(b"SCB2");
    header[4..12].copy_from_slice(&(proof_length as u64).to_le_bytes());
    header[12..].copy_from_slice(source_salt);
    Ok(header)
}
pub struct ComputedContributionBody {
    identity: [u8; 64],
    length: usize,
}
impl ComputedContributionBody {
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn length(&self) -> usize {
        self.length
    }
}
/// Exact ordinary body hashing, without an earlier commitment or a
/// whole-body salt. This computation verifies no contribution relation.
pub struct ContributionBodyHasher {
    hash: Option<IdentityHasher>,
    polynomials: Vec<(usize, usize)>,
    ordinal: usize,
    polynomial_offset: usize,
    proof_offset: usize,
    proof_length: usize,
    length: usize,
}
impl ContributionBodyHasher {
    pub fn new(profile: Profile, header: &[u8]) -> Result<Self, Error> {
        let proof_length = ContributionBodyHeader::decode(profile, header)?.proof_length;
        let polynomials: Vec<_> = profile
            .contribution_body_polynomials()
            .into_iter()
            .map(|index| (index, profile.setup_polynomial_bytes(index).unwrap()))
            .collect();
        let length =
            header.len() + polynomials.iter().map(|(_, bytes)| bytes).sum::<usize>() + proof_length;
        let mut hash = IdentityHasher::new(BODY_DOMAIN, &[], length)?;
        hash.absorb(header)?;
        Ok(Self {
            hash: Some(hash),
            polynomials,
            ordinal: 0,
            polynomial_offset: 0,
            proof_offset: 0,
            proof_length,
            length,
        })
    }
    pub fn next_polynomial(&self) -> Option<(usize, usize)> {
        self.polynomials.get(self.ordinal).copied()
    }
    pub fn push_polynomial(
        &mut self,
        index: usize,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let (expected, length) = self.next_polynomial().ok_or(Error::Shape)?;
        if index != expected
            || offset != self.polynomial_offset
            || bytes.is_empty()
            || bytes.len() > 1 << 20
            || bytes.len() > length - offset
        {
            return Err(Error::Shape);
        }
        self.hash.as_mut().ok_or(Error::Consumed)?.absorb(bytes)?;
        self.polynomial_offset += bytes.len();
        if self.polynomial_offset == length {
            self.ordinal += 1;
            self.polynomial_offset = 0;
        }
        Ok(())
    }
    pub fn push_proof(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        if self.next_polynomial().is_some()
            || offset != self.proof_offset
            || bytes.is_empty()
            || bytes.len() > 1 << 20
            || bytes.len() > self.proof_length - offset
        {
            return Err(Error::Shape);
        }
        self.hash.as_mut().ok_or(Error::Consumed)?.absorb(bytes)?;
        self.proof_offset += bytes.len();
        Ok(())
    }
    pub fn finish(mut self) -> Result<ComputedContributionBody, Error> {
        if self.next_polynomial().is_some() || self.proof_offset != self.proof_length {
            return Err(Error::Shape);
        }
        Ok(ComputedContributionBody {
            identity: self.hash.take().ok_or(Error::Consumed)?.finish()?,
            length: self.length,
        })
    }
}
