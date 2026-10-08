//! Registration commitments to original FHE encryption-key coordinates.
//! A digest fixes bytes; only the later contribution verifier checks their
//! complete key and encrypted-sharing relation.
use crate::{
    Credential, Error, SIGNING_PUBLIC_KEY_BYTES,
    foundation::CanonicalItem,
    identity::IdentityHasher,
    poll::VerifiedPoll,
    roster::{RetainedContributionContext, RosterProposal},
};
use supported_profile::{DEGREE, Profile};

pub const SOURCE_SALT_BYTES: usize = 64;

fn same_family(left: Profile, right: Profile) -> bool {
    left.ciphertext_modulus().to_bytes() == right.ciphertext_modulus().to_bytes()
        && left.fhe_common_sample_bits() == right.fhe_common_sample_bits()
}

fn families(maximum: usize, options: usize) -> Vec<Profile> {
    let mut families = Vec::new();
    for participants in *Profile::participant_range().start()..=maximum {
        let profile =
            Profile::new(participants, options).expect("A verified poll has supported dimensions.");
        if !families
            .iter()
            .any(|previous| same_family(*previous, profile))
        {
            families.push(profile);
        }
    }
    families
}

/// One representative per distinct modulus and common-sampler width, in
/// first-occurrence order among the rosters the verified poll permits.
/// The representative's participant count is not part of family framing.
pub fn fhe_key_families(poll: &VerifiedPoll) -> Vec<Profile> {
    families(
        usize::from(poll.maximum_participants()),
        poll.manifest().option_count(),
    )
}

pub fn fhe_key_family_index(poll: &VerifiedPoll, profile: Profile) -> Result<usize, Error> {
    if profile.options() != poll.manifest().option_count()
        || profile.participants() > usize::from(poll.maximum_participants())
    {
        return Err(Error::Context);
    }
    fhe_key_families(poll)
        .iter()
        .position(|family| same_family(*family, profile))
        .ok_or(Error::Context)
}

pub fn maximum_fhe_key_family_count() -> usize {
    Profile::option_range()
        .map(|options| families(*Profile::participant_range().end(), options).len())
        .max()
        .expect("Supported option range is nonempty.")
}

/// Hashes one exact canonical public coordinate, with at most one partial
/// coefficient retained across transport chunks. It creates no capability.
pub struct FheKeyCommitmentHasher {
    hash: Option<IdentityHasher>,
    length: usize,
    received: usize,
    half_modulus: Vec<u8>,
    coefficient: Vec<u8>,
}

impl FheKeyCommitmentHasher {
    pub fn for_registration(
        poll: &VerifiedPoll,
        credential: &Credential,
        profile: Profile,
        salt: &[u8; SOURCE_SALT_BYTES],
    ) -> Result<Self, Error> {
        fhe_key_family_index(poll, profile)?;
        Self::new(poll.identity(), credential.signing_public(), profile, salt)
    }

    pub fn for_contribution(
        proposal: &RosterProposal,
        position: usize,
        salt: &[u8; SOURCE_SALT_BYTES],
    ) -> Result<Self, Error> {
        proposal.fhe_key_commitment(position)?;
        let header = proposal
            .records()
            .get(position)
            .ok_or(Error::Context)?
            .header();
        Self::new(
            header.poll,
            &header.signing_public,
            proposal.profile(),
            salt,
        )
    }

    pub fn for_retained(
        context: &RetainedContributionContext,
        credential: &Credential,
        salt: &[u8; SOURCE_SALT_BYTES],
    ) -> Result<Self, Error> {
        if credential.completed_body != Some(context.owner_body) {
            return Err(Error::Context);
        }
        Self::new(
            context.poll,
            credential.signing_public(),
            context.profile(),
            salt,
        )
    }

    fn new(
        poll: [u8; 64],
        signing_public: &[u8; SIGNING_PUBLIC_KEY_BYTES],
        profile: Profile,
        salt: &[u8; SOURCE_SALT_BYTES],
    ) -> Result<Self, Error> {
        let modulus = profile.ciphertext_modulus().to_bytes();
        let length = DEGREE * (1 + modulus.len());
        let prefix = [
            CanonicalItem::fixed_bytes(signing_public).map_err(|_| Error::Shape)?,
            CanonicalItem::fixed_bytes(salt).map_err(|_| Error::Shape)?,
            CanonicalItem::hash512(poll),
            CanonicalItem::variable_bytes(&modulus).map_err(|_| Error::Shape)?,
            CanonicalItem::unsigned64(profile.fhe_common_sample_bits() as u64),
        ];
        let hash = IdentityHasher::local("sealed-lattice/registered-fhe-key/v1", &prefix, length)?;
        let mut half_modulus = modulus;
        let mut carry = 0;
        for byte in half_modulus.iter_mut().rev() {
            let next = (*byte & 1) << 7;
            *byte = (*byte >> 1) | carry;
            carry = next;
        }
        Ok(Self {
            hash: Some(hash),
            length,
            received: 0,
            coefficient: Vec::with_capacity(1 + half_modulus.len()),
            half_modulus,
        })
    }

    pub fn push(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        let Some(mut hash) = self.hash.take() else {
            return Err(Error::Consumed);
        };
        if offset != self.received
            || bytes.is_empty()
            || bytes.len() > 1 << 20
            || bytes.len() > self.length - self.received
        {
            return Err(Error::Shape);
        }
        let mut remaining = bytes;
        let width = 1 + self.half_modulus.len();
        while !remaining.is_empty() {
            let count = remaining.len().min(width - self.coefficient.len());
            self.coefficient.extend_from_slice(&remaining[..count]);
            remaining = &remaining[count..];
            if self.coefficient.len() == width {
                let magnitude = &self.coefficient[1..];
                if self.coefficient[0] > 1
                    || (self.coefficient[0] == 1 && magnitude.iter().all(|byte| *byte == 0))
                    || magnitude
                        .iter()
                        .rev()
                        .cmp(self.half_modulus.iter().rev())
                        .is_gt()
                {
                    return Err(Error::Shape);
                }
                self.coefficient.clear();
            }
        }
        hash.absorb(bytes)?;
        self.received += bytes.len();
        self.hash = Some(hash);
        Ok(())
    }

    pub fn finish(self) -> Result<[u8; 64], Error> {
        if self.received != self.length || !self.coefficient.is_empty() {
            return Err(Error::Shape);
        }
        self.hash.ok_or(Error::Consumed)?.finish()
    }
}

#[cfg(test)]
#[path = "source-binding-tests.rs"]
mod tests;
