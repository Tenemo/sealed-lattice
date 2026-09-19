use crate::{
    Credential, Error,
    foundation::{CanonicalItem, hash::StreamingFoundationTupleHash512},
    roster::{RetainedContributionContext, RosterProposal},
};
use zeroize::Zeroizing;

pub struct ComputedContributionCommitment {
    pub(crate) proposal: [u8; 64],
    pub(crate) position: usize,
    pub(crate) digest: [u8; 64],
    pub(crate) salt: Zeroizing<[u8; 64]>,
}
impl ComputedContributionCommitment {
    pub fn digest(&self) -> &[u8; 64] {
        &self.digest
    }
}

pub const MINIMUM_PROOF_BYTES: usize = 4004;
pub const MAXIMUM_PROOF_BYTES: usize = 41_991_008;
const POLYNOMIAL_BYTES: usize = 24 * 65536 * 109 + 20 * 65536 * 21 + 4096 * 6;

pub fn body_header(proof_length: usize) -> Result<[u8; 12], Error> {
    if !(MINIMUM_PROOF_BYTES..=MAXIMUM_PROOF_BYTES).contains(&proof_length) {
        return Err(Error::Shape);
    }
    let mut header = [0; 12];
    header[..4].copy_from_slice(b"SCB1");
    header[4..].copy_from_slice(&(proof_length as u64).to_le_bytes());
    Ok(header)
}

fn polynomial(ordinal: usize) -> Option<(usize, usize)> {
    match ordinal {
        0..24 => Some((7 * (ordinal / 4) + [1, 2, 4, 6][ordinal % 4], 65536 * 109)),
        24..44 => Some((
            44 + 3 * ((ordinal - 24) / 2) + (ordinal - 24) % 2,
            65536 * 21,
        )),
        44 => Some((74, 4096 * 6)),
        _ => None,
    }
}

/// Hashes a framed body. It does not verify the contribution relation,
/// authorize a confirmation, or consume a participant's local signing lock.
pub struct ContributionCommitmentHasher {
    hash: Option<StreamingFoundationTupleHash512>,
    ordinal: usize,
    polynomial_offset: usize,
    proof_offset: usize,
    proof_length: usize,
    proposal: [u8; 64],
    position: usize,
    salt: Zeroizing<[u8; 64]>,
}
impl ContributionCommitmentHasher {
    pub fn new(
        proposal: &RosterProposal,
        position: usize,
        salt: &[u8; 64],
        header: &[u8],
    ) -> Result<Self, Error> {
        let role = proposal.contribution_role(position)?;
        let record = proposal.records().get(position).ok_or(Error::Context)?;
        Self::from_parts(
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
        salt: &[u8; 64],
        header: &[u8],
    ) -> Result<Self, Error> {
        credential.validate_retained_confirmation(context)?;
        Self::from_parts(
            context.proposal,
            context.position,
            credential.signing_public(),
            context.role(),
            salt,
            header,
        )
    }
    fn from_parts(
        proposal: [u8; 64],
        position: usize,
        signing_public: &[u8; 1952],
        role: &[u8],
        salt: &[u8; 64],
        header: &[u8],
    ) -> Result<Self, Error> {
        if header.len() != 12 || &header[..4] != b"SCB1" {
            return Err(Error::Shape);
        }
        let proof_length = usize::try_from(u64::from_le_bytes(header[4..].try_into().unwrap()))
            .map_err(|_| Error::Shape)?;
        if body_header(proof_length)?.as_slice() != header {
            return Err(Error::Shape);
        }
        let prefix = [
            CanonicalItem::fixed_bytes(*signing_public).map_err(|_| Error::Shape)?,
            CanonicalItem::fixed_bytes(*salt).map_err(|_| Error::Shape)?,
            CanonicalItem::variable_bytes(role).map_err(|_| Error::Shape)?,
        ];
        let mut hash = StreamingFoundationTupleHash512::new_variable_bytes(
            "sealed-lattice/setup-commitment/v1",
            &prefix,
            header.len() + POLYNOMIAL_BYTES + proof_length,
        )
        .map_err(|_| Error::Shape)?;
        hash.absorb(header).map_err(|_| Error::Shape)?;
        Ok(Self {
            hash: Some(hash),
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
        polynomial(self.ordinal)
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
            .finalize()
            .map(|hash| ComputedContributionCommitment {
                proposal: self.proposal,
                position: self.position,
                digest: hash.into_bytes(),
                salt: Zeroizing::new(std::mem::replace(&mut *self.salt, [0; 64])),
            })
            .map_err(|_| Error::Shape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::CanonicalTuple;

    #[test]
    fn emitted_hash_matches_canonical_sender_prefix() {
        let public_key = std::array::from_fn::<_, 1952, _>(|index| (index % 251) as u8);
        let salt = [4; 64];
        let role =
            crate::roster::contribution_role_from_context([1; 64], [2; 64], [3; 64], 7).unwrap();
        let zeros = vec![0u8; 1 << 20];
        let hexadecimal = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|value| format!("{value:02x}"))
                .collect::<String>()
        };
        for proof_length in [MINIMUM_PROOF_BYTES, MAXIMUM_PROOF_BYTES] {
            let header = body_header(proof_length).unwrap();
            let payload_length = header.len() + POLYNOMIAL_BYTES + proof_length;
            let mut prefix = CanonicalTuple::new(
                1,
                1,
                vec![
                    CanonicalItem::nonempty_ascii("sealed-lattice/setup-commitment/v1").unwrap(),
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
                [3; 64],
                7,
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
                "COMMITMENT-FRAME|{proof_length}|{}|{}|{}|{elapsed}",
                hexadecimal(&prefix),
                hexadecimal(&header),
                hexadecimal(commitment.digest())
            );
        }
    }

    #[test]
    fn layout_covers_every_owned_polynomial_once() {
        let values = (0..45)
            .map(|ordinal| polynomial(ordinal).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            values.iter().map(|(_, bytes)| bytes).sum::<usize>(),
            POLYNOMIAL_BYTES
        );
        assert!(values.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(polynomial(45), None);
        assert!(body_header(MINIMUM_PROOF_BYTES).is_ok());
        assert!(body_header(MAXIMUM_PROOF_BYTES).is_ok());
        assert!(body_header(MINIMUM_PROOF_BYTES - 1).is_err());
        assert!(body_header(MAXIMUM_PROOF_BYTES + 1).is_err());
    }
}
