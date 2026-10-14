use crate::{Refusal, identity::BodyHasher};
use std::ops::RangeInclusive;
use supported_profile::{
    AUXILIARY_DEGREE, DEGREE, Profile, auxiliary_modulus,
    relation::{BALLOT_HEADER_BYTES, PROOF_HEADER_BYTES, ballot_relation},
};

pub(crate) const CONTEXT_BYTES: usize = BALLOT_HEADER_BYTES;
/// The body header: its magic, the complete proof length, the statement
/// context and the proof header. It opens the proof's verification, so the
/// ciphertexts that follow it stream into the statement as they arrive, and
/// the rest of the proof ends the body.
pub const HEADER_BYTES: usize = 12 + CONTEXT_BYTES + PROOF_HEADER_BYTES;
pub(crate) const BODY_DOMAIN: &str = "sealed-lattice/ballot-body/v1";

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
/// The length of a body whose complete proof has the length.
pub fn body_length(profile: Profile, proof_length: usize) -> usize {
    HEADER_BYTES + ciphertext_bytes(profile) + proof_length - PROOF_HEADER_BYTES
}
pub fn body_lengths(profile: Profile) -> RangeInclusive<usize> {
    let proofs = proof_lengths(profile);
    body_length(profile, *proofs.start())..=body_length(profile, *proofs.end())
}

/// Checks a ballot statement header: it names a roster position of the
/// profile, the poll's option count and a result length of at least one
/// option and at most every option.
pub fn check_context(profile: Profile, context: &[u8]) -> Result<(), Refusal> {
    if context.len() != CONTEXT_BYTES
        || &context[..4] != b"LBS1"
        || usize::from(context[134]) != profile.options()
        || context[135] == 0
        || context[135] > context[134]
        || usize::from(u16::from_le_bytes(context[132..134].try_into().unwrap()))
            >= profile.participants()
    {
        return Err(Refusal::Shape);
    }
    Ok(())
}
/// The body header of a ballot statement header and its complete proof.
pub fn header(profile: Profile, context: &[u8], proof: &[u8]) -> Result<Vec<u8>, Refusal> {
    check_context(profile, context)?;
    if !proof_lengths(profile).contains(&proof.len()) {
        return Err(Refusal::Shape);
    }
    let mut bytes = Vec::from(b"LBB1".as_slice());
    bytes.extend((proof.len() as u64).to_le_bytes());
    bytes.extend(context);
    bytes.extend(&proof[..PROOF_HEADER_BYTES]);
    Ok(bytes)
}
/// The parts of a body header.
pub struct BodyHeader<'a> {
    pub proof_length: usize,
    pub context: &'a [u8],
    pub proof_header: &'a [u8],
}
pub fn parse_header(profile: Profile, bytes: &[u8]) -> Result<BodyHeader<'_>, Refusal> {
    if bytes.len() != HEADER_BYTES || &bytes[..4] != b"LBB1" {
        return Err(Refusal::Shape);
    }
    let proof_length = usize::try_from(u64::from_le_bytes(bytes[4..12].try_into().unwrap()))
        .map_err(|_| Refusal::Shape)?;
    let (context, proof_header) = bytes[12..].split_at(CONTEXT_BYTES);
    check_context(profile, context)?;
    if !proof_lengths(profile).contains(&proof_length) {
        return Err(Refusal::Shape);
    }
    Ok(BodyHeader {
        proof_length,
        context,
        proof_header,
    })
}
/// The hasher of a ballot body of the length. It hashes the committed bytes
/// even if their inner header or proof is malformed: completion supplies a
/// byte identity, not semantic validity.
pub fn body_hasher(profile: Profile, length: usize) -> Result<BodyHasher, Refusal> {
    if !body_lengths(profile).contains(&length) {
        return Err(Refusal::Shape);
    }
    BodyHasher::new(BODY_DOMAIN, length)
}
/// The hasher of the ballot body that the canonical header begins, after
/// the header.
pub fn header_body_hasher(profile: Profile, header: &[u8]) -> Result<BodyHasher, Refusal> {
    let length = body_length(profile, parse_header(profile, header)?.proof_length);
    let mut hash = body_hasher(profile, length)?;
    hash.push(header)?;
    Ok(hash)
}

#[cfg(test)]
#[path = "ballot-body-tests.rs"]
mod tests;
