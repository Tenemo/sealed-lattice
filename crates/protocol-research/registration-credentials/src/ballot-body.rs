use crate::{Error, foundation::hash::StreamingFoundationTupleHash512};
use std::ops::RangeInclusive;
use supported_profile::{
    AUXILIARY_DEGREE, DEGREE, Profile, auxiliary_modulus,
    relation::{BALLOT_HEADER_BYTES, PROOF_HEADER_BYTES, ballot_relation},
};

pub const CONTEXT_BYTES: usize = BALLOT_HEADER_BYTES;
pub const HEADER_BYTES: usize = 12 + CONTEXT_BYTES;
pub const BODY_DOMAIN: &str = "sealed-lattice/ballot-body/v1";

/// The body's ciphertext polynomials, by ballot statement index, with their
/// byte lengths: both FHE ciphertext components, then both auxiliary
/// ciphertext components.
pub fn polynomials(profile: Profile) -> [(usize, usize); 4] {
    let fhe = DEGREE * (1 + profile.ciphertext_modulus().byte_length());
    let auxiliary = AUXILIARY_DEGREE * (1 + auxiliary_modulus().len());
    [(2, fhe), (3, fhe), (6, auxiliary), (7, auxiliary)]
}
pub fn polynomial(profile: Profile, ordinal: usize) -> Option<(usize, usize)> {
    polynomials(profile).get(ordinal).copied()
}
pub fn ciphertext_bytes(profile: Profile) -> usize {
    polynomials(profile).iter().map(|(_, bytes)| bytes).sum()
}
pub fn proof_lengths(profile: Profile) -> RangeInclusive<usize> {
    PROOF_HEADER_BYTES..=ballot_relation(profile).maximum_proof_bytes()
}
pub fn body_lengths(profile: Profile) -> RangeInclusive<usize> {
    let fixed = HEADER_BYTES + ciphertext_bytes(profile);
    let proofs = proof_lengths(profile);
    fixed + proofs.start()..=fixed + proofs.end()
}

/// Checks a ballot statement header: it names a roster position of the
/// profile, the poll's option count and a result length of at least one
/// option and at most every option.
pub fn check_context(profile: Profile, context: &[u8]) -> Result<(), Error> {
    if context.len() != CONTEXT_BYTES
        || &context[..4] != b"LBS1"
        || usize::from(context[134]) != profile.options()
        || context[135] == 0
        || context[135] > context[134]
        || usize::from(u16::from_le_bytes(context[132..134].try_into().unwrap()))
            >= profile.participants()
    {
        return Err(Error::Shape);
    }
    Ok(())
}
/// The body header of a ballot statement header.
pub fn header(profile: Profile, context: &[u8], proof_length: usize) -> Result<Vec<u8>, Error> {
    check_context(profile, context)?;
    if !proof_lengths(profile).contains(&proof_length) {
        return Err(Error::Shape);
    }
    let mut bytes = Vec::from(b"LBB1".as_slice());
    bytes.extend((proof_length as u64).to_le_bytes());
    bytes.extend(context);
    Ok(bytes)
}
pub fn proof_length(profile: Profile, bytes: &[u8]) -> Result<usize, Error> {
    if bytes.len() != HEADER_BYTES || &bytes[..4] != b"LBB1" {
        return Err(Error::Shape);
    }
    let length = usize::try_from(u64::from_le_bytes(bytes[4..12].try_into().unwrap()))
        .map_err(|_| Error::Shape)?;
    if header(profile, &bytes[12..], length)? != bytes {
        return Err(Error::Shape);
    }
    Ok(length)
}
/// Computes the exact framed body identity; it supplies no proof or signing authority.
pub struct BallotBodyHasher {
    hash: Option<StreamingFoundationTupleHash512>,
    remaining: usize,
}
impl BallotBodyHasher {
    pub fn new(profile: Profile, header: &[u8]) -> Result<Self, Error> {
        let remaining = ciphertext_bytes(profile) + proof_length(profile, header)?;
        let mut hash = Self::for_body_length(profile, HEADER_BYTES + remaining)?;
        hash.push(header)?;
        Ok(hash)
    }
    /// Hashes the committed bytes even if their inner header or proof is malformed.
    /// Completion supplies a byte identity, not semantic validity.
    pub fn for_body_length(profile: Profile, length: usize) -> Result<Self, Error> {
        if !body_lengths(profile).contains(&length) {
            return Err(Error::Shape);
        }
        let hash = StreamingFoundationTupleHash512::new_variable_bytes(BODY_DOMAIN, &[], length)
            .map_err(|_| Error::Shape)?;
        Ok(Self {
            hash: Some(hash),
            remaining: length,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > 1 << 20 || bytes.len() > self.remaining {
            self.hash = None;
            return Err(Error::Shape);
        }
        self.hash
            .as_mut()
            .ok_or(Error::Consumed)?
            .absorb(bytes)
            .map_err(|_| Error::Shape)?;
        self.remaining -= bytes.len();
        Ok(())
    }
    pub fn finish(mut self) -> Result<[u8; 64], Error> {
        if self.remaining != 0 {
            return Err(Error::Shape);
        }
        self.hash
            .take()
            .ok_or(Error::Consumed)?
            .finalize()
            .map(|hash| hash.into_bytes())
            .map_err(|_| Error::Shape)
    }
}

#[cfg(test)]
#[path = "ballot-body-tests.rs"]
mod tests;
