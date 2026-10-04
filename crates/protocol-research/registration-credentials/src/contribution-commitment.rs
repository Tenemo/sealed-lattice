use crate::{
    Credential, Error,
    foundation::CanonicalItem,
    identity::IdentityHasher,
    roster::{RetainedContributionContext, RosterProposal},
};
use std::ops::RangeInclusive;
use supported_profile::{
    Profile,
    relation::{PROOF_HEADER_BYTES, setup_relation},
};
use zeroize::Zeroizing;

/// A contribution commitment's secret salt.
pub const SALT_BYTES: usize = 64;
/// A contribution body opens with its magic, proof length and the original
/// registration-coordinate opening salt. The whole-body salt stays separate.
pub const BODY_HEADER_BYTES: usize = 4 + 8 + crate::source_binding::SOURCE_SALT_BYTES;

pub struct ContributionBodyHeader {
    pub proof_length: usize,
    pub source_salt: [u8; crate::source_binding::SOURCE_SALT_BYTES],
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

pub struct ComputedContributionCommitment {
    pub(crate) proposal: [u8; 64],
    pub(crate) position: usize,
    pub(crate) digest: [u8; 64],
    pub(crate) salt: Zeroizing<[u8; SALT_BYTES]>,
}
impl ComputedContributionCommitment {
    pub fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
}

pub fn proof_lengths(profile: Profile) -> RangeInclusive<usize> {
    PROOF_HEADER_BYTES..=setup_relation(profile).maximum_proof_bytes()
}

pub fn body_header(
    profile: Profile,
    proof_length: usize,
    source_salt: &[u8; crate::source_binding::SOURCE_SALT_BYTES],
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

/// The body's polynomials in order, each by setup index with its byte length.
fn polynomials(profile: Profile) -> Vec<(usize, usize)> {
    profile
        .contribution_body_polynomials()
        .into_iter()
        .map(|index| (index, profile.setup_polynomial_bytes(index).unwrap()))
        .collect()
}

/// Hashes a framed body. It does not verify the contribution relation,
/// authorize a confirmation, or consume a participant's local signing lock.
pub struct ContributionCommitmentHasher {
    hash: Option<IdentityHasher>,
    polynomials: Vec<(usize, usize)>,
    ordinal: usize,
    polynomial_offset: usize,
    proof_offset: usize,
    proof_length: usize,
    proposal: [u8; 64],
    position: usize,
    salt: Zeroizing<[u8; SALT_BYTES]>,
}
impl ContributionCommitmentHasher {
    pub fn new(
        proposal: &RosterProposal,
        position: usize,
        salt: &[u8; SALT_BYTES],
        header: &[u8],
    ) -> Result<Self, Error> {
        let role = proposal.contribution_role(position)?;
        let record = proposal.records().get(position).ok_or(Error::Context)?;
        Self::from_parts(
            proposal.profile(),
            proposal.identity(),
            position,
            &record.header().signing_public,
            &role,
            salt,
            header,
        )
    }
    pub fn from_retained(
        credential: &Credential,
        context: &RetainedContributionContext,
        salt: &[u8; SALT_BYTES],
        header: &[u8],
    ) -> Result<Self, Error> {
        credential.validate_retained_confirmation(context)?;
        Self::from_parts(
            context.profile(),
            context.proposal,
            context.position,
            credential.signing_public(),
            context.role(),
            salt,
            header,
        )
    }
    fn from_parts(
        profile: Profile,
        proposal: [u8; 64],
        position: usize,
        signing_public: &[u8; 1952],
        role: &[u8],
        salt: &[u8; SALT_BYTES],
        header: &[u8],
    ) -> Result<Self, Error> {
        let proof_length = ContributionBodyHeader::decode(profile, header)?.proof_length;
        let polynomials = polynomials(profile);
        let prefix = [
            CanonicalItem::fixed_bytes(*signing_public).map_err(|_| Error::Shape)?,
            CanonicalItem::fixed_bytes(*salt).map_err(|_| Error::Shape)?,
            CanonicalItem::variable_bytes(role).map_err(|_| Error::Shape)?,
        ];
        let mut hash = IdentityHasher::new(
            "sealed-lattice/setup-commitment/v1",
            &prefix,
            header.len() + polynomials.iter().map(|(_, bytes)| bytes).sum::<usize>() + proof_length,
        )?;
        hash.absorb(header)?;
        Ok(Self {
            hash: Some(hash),
            polynomials,
            ordinal: 0,
            polynomial_offset: 0,
            proof_offset: 0,
            proof_length,
            proposal,
            position,
            salt: Zeroizing::new(*salt),
        })
    }
    pub fn next_polynomial(&self) -> Option<(usize, usize)> {
        self.polynomials.get(self.ordinal).copied()
    }
    pub fn push_polynomial(
        &mut self,
        expanded_index: usize,
        offset: usize,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let (expected, length) = self.next_polynomial().ok_or(Error::Shape)?;
        if expanded_index != expected
            || offset != self.polynomial_offset
            || bytes.is_empty()
            || bytes.len() > 1 << 20
            || bytes.len() > length - self.polynomial_offset
        {
            return Err(Error::Shape);
        }
        self.hash
            .as_mut()
            .ok_or(Error::Consumed)?
            .absorb(bytes)
            .map_err(|_| Error::Shape)?;
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
            || bytes.len() > self.proof_length - self.proof_offset
        {
            return Err(Error::Shape);
        }
        self.hash
            .as_mut()
            .ok_or(Error::Consumed)?
            .absorb(bytes)
            .map_err(|_| Error::Shape)?;
        self.proof_offset += bytes.len();
        Ok(())
    }
    pub fn finish(&mut self) -> Result<ComputedContributionCommitment, Error> {
        if self.next_polynomial().is_some() || self.proof_offset != self.proof_length {
            return Err(Error::Shape);
        }
        self.hash
            .take()
            .ok_or(Error::Consumed)?
            .finish()
            .map(|digest| ComputedContributionCommitment {
                proposal: self.proposal,
                position: self.position,
                digest,
                salt: Zeroizing::new(std::mem::replace(&mut *self.salt, [0; SALT_BYTES])),
            })
            .map_err(|_| Error::Shape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::CanonicalTuple;

    #[test]
    fn body_header_binds_the_source_opening_and_rejects_other_formats() {
        let profile = Profile::new(3, 2).unwrap();
        let length = *proof_lengths(profile).start();
        let bytes = body_header(profile, length, &[9; 64]).unwrap();
        let parsed = ContributionBodyHeader::decode(profile, &bytes).unwrap();
        assert_eq!(parsed.proof_length, length);
        assert_eq!(parsed.source_salt, [9; 64]);
        let mut changed = bytes;
        changed[3] = b'1';
        assert!(ContributionBodyHeader::decode(profile, &changed).is_err());
        assert!(ContributionBodyHeader::decode(profile, &bytes[..12]).is_err());
        assert!(
            ContributionBodyHeader::decode(profile, &[bytes.as_slice(), &[0]].concat()).is_err()
        );
        changed = bytes;
        changed[4..12].copy_from_slice(&(length as u64 - 1).to_le_bytes());
        assert!(ContributionBodyHeader::decode(profile, &changed).is_err());
    }

    #[test]
    fn emitted_hash_matches_canonical_sender_prefix() {
        let public_key = std::array::from_fn::<_, 1952, _>(|index| (index % 251) as u8);
        let salt = [4; 64];
        let role = crate::roster::encode_contribution_role(
            [1; 64],
            [2; 64],
            [3; 64],
            2,
            crate::foundation::participant_identity::derive_participant_identity(&public_key)
                .unwrap(),
        )
        .unwrap();
        let zeros = vec![0u8; 1 << 20];
        let hexadecimal = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|value| format!("{value:02x}"))
                .collect::<String>()
        };
        for (participants, options) in [(3, 2), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            let proofs = proof_lengths(profile);
            let polynomial_bytes: usize = polynomials(profile).iter().map(|(_, bytes)| bytes).sum();
            for proof_length in [*proofs.start(), *proofs.end()] {
                let header = body_header(profile, proof_length, &[6; 64]).unwrap();
                let payload_length = header.len() + polynomial_bytes + proof_length;
                let mut prefix = CanonicalTuple::new(
                    1,
                    1,
                    vec![
                        CanonicalItem::nonempty_ascii("sealed-lattice/setup-commitment/v1")
                            .unwrap(),
                        CanonicalItem::fixed_bytes(public_key).unwrap(),
                        CanonicalItem::fixed_bytes(salt).unwrap(),
                        CanonicalItem::variable_bytes(&role).unwrap(),
                        CanonicalItem::variable_bytes([]).unwrap(),
                    ],
                )
                .encode()
                .unwrap();
                // The final empty raw-byte item has no payload. Replace only its
                // two length words to obtain the complete stream's actual prefix.
                let end = prefix.len();
                prefix[end - 8..end - 4]
                    .copy_from_slice(&u32::try_from(payload_length + 4).unwrap().to_le_bytes());
                prefix[end - 4..]
                    .copy_from_slice(&u32::try_from(payload_length).unwrap().to_le_bytes());
                let start = std::time::Instant::now();
                let mut hasher = ContributionCommitmentHasher::from_parts(
                    profile,
                    [3; 64],
                    2,
                    &public_key,
                    &role,
                    &salt,
                    &header,
                )
                .unwrap();
                assert!(hasher.finish().is_err());
                while let Some((polynomial, length)) = hasher.next_polynomial() {
                    let mut offset = 0;
                    while offset < length {
                        let amount = zeros.len().min(length - offset);
                        hasher
                            .push_polynomial(polynomial, offset, &zeros[..amount])
                            .unwrap();
                        offset += amount;
                    }
                }
                let mut offset = 0;
                while offset < proof_length {
                    let amount = zeros.len().min(proof_length - offset);
                    hasher.push_proof(offset, &zeros[..amount]).unwrap();
                    offset += amount;
                }
                let commitment = hasher.finish().unwrap();
                let elapsed = start.elapsed().as_millis();
                assert!(hasher.finish().is_err());
                println!(
                    "COMMITMENT-FRAME|{participants}|{options}|{proof_length}|{}|{}|{}|{elapsed}",
                    hexadecimal(&prefix),
                    hexadecimal(&header),
                    hexadecimal(commitment.digest())
                );
            }
        }
    }

    #[test]
    fn layout_follows_the_profile_and_refuses_other_polynomials() {
        for (participants, options) in [(3, 2), (10, 10), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            let values = polynomials(profile);
            assert_eq!(
                values.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
                profile.contribution_body_polynomials()
            );
            let proofs = proof_lengths(profile);
            assert!(body_header(profile, *proofs.start(), &[6; 64]).is_ok());
            assert!(body_header(profile, *proofs.end(), &[6; 64]).is_ok());
            assert!(body_header(profile, proofs.start() - 1, &[6; 64]).is_err());
            assert!(body_header(profile, proofs.end() + 1, &[6; 64]).is_err());
            let header = body_header(profile, *proofs.start(), &[6; 64]).unwrap();
            let mut hasher = ContributionCommitmentHasher::from_parts(
                profile, [3; 64], 0, &[5; 1952], b"role", &[4; 64], &header,
            )
            .unwrap();
            let (first, length) = hasher.next_polynomial().unwrap();
            // A polynomial out of order, an offset gap, or bytes past the
            // polynomial's end are refused, and so is a proof before the
            // last polynomial.
            assert!(hasher.push_polynomial(values[1].0, 0, &[0]).is_err());
            assert!(hasher.push_polynomial(first, 1, &[0]).is_err());
            assert!(hasher.push_proof(0, &[0]).is_err());
            assert!(
                hasher
                    .push_polynomial(first, 0, &vec![0; (length).min(1 << 20)])
                    .is_ok()
            );
        }
        // The completion profile's body model: 24 FHE keys, 20 share
        // encryptions and the auxiliary key, with the setup proof bound.
        let completion = Profile::new(10, 10).unwrap();
        assert_eq!(polynomials(completion).len(), 45);
        assert_eq!(*proof_lengths(completion).end(), 41_855_840);
        let longest = Profile::new(20, 20).unwrap();
        assert!(body_header(completion, *proof_lengths(longest).end(), &[6; 64]).is_err());
    }
}
