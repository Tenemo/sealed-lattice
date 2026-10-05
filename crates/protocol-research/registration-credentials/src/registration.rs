use crate::{
    BodyDigest, Error, foundation::RegistrationHeader, poll::VerifiedPoll,
    verify_registration_signature,
};
use parallel_work::ProtocolHash;

#[path = "retained-registration.rs"]
mod retained;
#[path = "registration-session.rs"]
pub mod session;
pub use retained::RETAINED_REGISTRATION_BYTES;

pub const CHUNK_LIMIT: usize = 1 << 20;
pub const KEY_BYTES: usize = supported_profile::DEGREE * 21;

pub struct VerifiedRegistration {
    header: RegistrationHeader,
    body_digest: [u8; 64],
    public_key: Vec<u8>,
}
impl VerifiedRegistration {
    pub fn header(&self) -> &RegistrationHeader {
        &self.header
    }
    pub fn body_digest(&self) -> [u8; 64] {
        self.body_digest
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
    pub(crate) fn restored(
        header: RegistrationHeader,
        body_digest: [u8; 64],
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            header,
            body_digest,
            public_key,
        }
    }
    #[cfg(test)]
    pub(crate) fn for_roster(header: RegistrationHeader, body_digest: [u8; 64]) -> Self {
        Self {
            header,
            body_digest,
            public_key: Vec::new(),
        }
    }
}

// Canonical centered coefficients are required independently of any proof.
// Check bytes directly: signs are 0/1, zero is positive, and magnitude is at
// most floor(q/2). No bound on a corrupt recipient's secret is assumed here.
pub(crate) fn canonical_key(bytes: &[u8]) -> bool {
    if bytes.len() != KEY_BYTES {
        return false;
    }
    let mut half = supported_profile::share_modulus().to_vec();
    let mut carry = 0;
    for byte in half.iter_mut().rev() {
        let next = (*byte & 1) << 7;
        *byte = (*byte >> 1) | carry;
        carry = next;
    }
    bytes.chunks_exact(1 + half.len()).all(|coefficient| {
        coefficient[0] <= 1
            && (coefficient[0] == 0 || coefficient[1..].iter().any(|byte| *byte != 0))
            && coefficient[1..].iter().rev().cmp(half.iter().rev()) != std::cmp::Ordering::Greater
    })
}

pub struct RegistrationVerifier {
    header: RegistrationHeader,
    body: BodyDigest,
    signature: [u8; 3309],
    key: Vec<u8>,
    key_finished: bool,
    failed: bool,
}
impl RegistrationVerifier {
    pub fn new(poll: &VerifiedPoll, header_bytes: &[u8], signature: &[u8]) -> Result<Self, Error> {
        crate::checked_header(header_bytes, poll)?;
        Self::open(poll.identity(), poll.runtime(), header_bytes, signature)
    }
    fn open(
        poll: [u8; 64],
        runtime: [u8; 64],
        header_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Self, Error> {
        let (header, consumed) = RegistrationHeader::decode_prefix(header_bytes)?;
        if consumed != header_bytes.len() {
            return Err(Error::Shape);
        }
        let body = BodyDigest::from_header(header_bytes, poll, runtime)?;
        Ok(Self {
            header,
            body,
            signature: signature.try_into().map_err(|_| Error::Shape)?,
            key: Vec::with_capacity(KEY_BYTES),
            key_finished: false,
            failed: false,
        })
    }
    pub fn push_key(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.failed
            || self.key_finished
            || bytes.len() > CHUNK_LIMIT
            || bytes.len() > KEY_BYTES - self.key.len()
        {
            self.failed = true;
            return Err(Error::Shape);
        }
        self.key.extend(bytes);
        Ok(())
    }
    pub fn finish_key(&mut self) -> Result<(), Error> {
        if self.failed
            || self.key_finished
            || !canonical_key(&self.key)
            || ProtocolHash::digest(&self.key) != self.header.recipient_key_hash
        {
            self.failed = true;
            return Err(Error::Shape);
        }
        self.key_finished = true;
        Ok(())
    }
    pub fn finish(self) -> Result<VerifiedRegistration, Error> {
        if self.failed || !self.key_finished {
            return Err(Error::Consumed);
        }
        let body_digest = self.body.bytes();
        if !verify_registration_signature(self.body, &self.signature) {
            return Err(Error::Crypto);
        }
        Ok(VerifiedRegistration {
            header: self.header,
            body_digest,
            public_key: self.key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Credential,
        foundation::{
            StabilizedDisplayText,
            ceremony::{Manifest, OptionDefinition},
            normalize_username,
        },
        poll::{PollDraft, verify_poll},
        roster::RosterProposal,
    };
    use std::sync::Arc;
    use supported_profile::Profile;

    fn recipient_poll() -> VerifiedPoll {
        let text =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        let options = (0..2)
            .map(|index| {
                OptionDefinition::new(
                    index,
                    format!("option-{index}"),
                    text(&format!("Option {index}")),
                )
                .unwrap()
            })
            .collect();
        let draft =
            PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 1, 4).unwrap();
        let packet = Credential::from_seed([1; 32])
            .create_poll(draft, [4; 64], [5; 32])
            .unwrap();
        verify_poll(packet.identity, [4; 64], &packet.body, &packet.signature).unwrap()
    }

    // Sign the hash of the actual test key, including malformed encodings,
    // so these refusals cannot be supplied by a stale digest or signature.
    fn verify_key(
        poll: &VerifiedPoll,
        key: &[u8],
        seed: u8,
        chunk: usize,
    ) -> Result<VerifiedRegistration, Error> {
        let mut credential = Credential::from_seed([seed; 32]);
        let header = RegistrationHeader {
            username: normalize_username(format!("Participant {seed}").as_bytes()).unwrap(),
            poll: poll.identity(),
            runtime: poll.runtime(),
            signing_public: *credential.signing_public(),
            recipient_key_hash: ProtocolHash::digest(key),
            fhe_key_commitments: vec![[7; 64]; crate::source_binding::fhe_key_families(poll).len()],
        }
        .encode()?;
        let body = BodyDigest::from_header(&header, poll.identity(), poll.runtime())?;
        let signature = credential.sign_registration(body)?;
        let mut verifier = RegistrationVerifier::new(poll, &header, &signature)?;
        for part in key.chunks(chunk) {
            verifier.push_key(part)?;
        }
        verifier.finish_key()?;
        verifier.finish()
    }

    #[test]
    fn registration_accepts_zero_copied_and_arbitrary_canonical_recipient_keys() {
        let poll = recipient_poll();
        let zero = vec![0; KEY_BYTES];
        let first = verify_key(&poll, &zero, 2, 65_543).unwrap();
        let copied = verify_key(&poll, first.public_key(), 3, CHUNK_LIMIT).unwrap();
        assert_eq!(first.public_key(), copied.public_key());
        assert_ne!(
            first.header().signing_public,
            copied.header().signing_public
        );
        assert_ne!(first.body_digest(), copied.body_digest());
        let mut arbitrary = zero;
        for (position, coefficient) in arbitrary.chunks_exact_mut(21).enumerate() {
            coefficient[0] = (position % 2) as u8;
            coefficient[1] = 1 + (position % 255) as u8;
        }
        assert_eq!(
            verify_key(&poll, &arbitrary, 4, 4_099)
                .unwrap()
                .public_key(),
            arbitrary
        );
    }

    #[test]
    fn signed_recipient_keys_still_require_canonical_centered_coefficients() {
        let poll = recipient_poll();
        let modulus = supported_profile::share_modulus();
        // Independent bit indexing computes floor(q/2), rather than the
        // verifier's byte-carry division.
        let mut half = [0u8; 20];
        for bit in 0..159 {
            half[bit / 8] |= ((modulus[(bit + 1) / 8] >> ((bit + 1) % 8)) & 1) << (bit % 8);
        }
        for sign in [0, 1] {
            let mut key = vec![0; KEY_BYTES];
            let last = &mut key[KEY_BYTES - 21..];
            last[0] = sign;
            last[1..].copy_from_slice(&half);
            assert!(verify_key(&poll, &key, 2, CHUNK_LIMIT).is_ok());
            for byte in &mut key[KEY_BYTES - 20..] {
                let (value, carry) = byte.overflowing_add(1);
                *byte = value;
                if !carry {
                    break;
                }
            }
            assert!(verify_key(&poll, &key, 2, CHUNK_LIMIT).is_err());
        }
        for sign in [1, 2, 255] {
            let mut key = vec![0; KEY_BYTES];
            key[21] = sign;
            assert!(verify_key(&poll, &key, 2, 65_543).is_err());
        }
        for length in [KEY_BYTES - 1, KEY_BYTES + 1] {
            assert!(verify_key(&poll, &vec![0; length], 2, CHUNK_LIMIT).is_err());
        }
    }

    #[test]
    fn every_supported_roster_size_up_to_the_poll_maximum_can_be_proposed() {
        let text =
            |value: &str| StabilizedDisplayText::from_ingress_utf8(value.as_bytes()).unwrap();
        let poll = |maximum: usize| {
            let options = (0..10)
                .map(|index| {
                    OptionDefinition::new(
                        index,
                        format!("option-{index}"),
                        text(&format!("Option {index}")),
                    )
                    .unwrap()
                })
                .collect();
            let draft = PollDraft::new(
                Manifest::new(text("Question"), options).unwrap(),
                1,
                maximum as u16,
            )
            .unwrap();
            let packet = Credential::from_seed([1; 32])
                .create_poll(draft, [4; 64], [5; 32])
                .unwrap();
            verify_poll(packet.identity, [4; 64], &packet.body, &packet.signature).unwrap()
        };
        let organizer = Credential::from_seed([1; 32]);
        let members: Vec<_> = (10..30)
            .map(|seed| Credential::from_seed([seed; 32]))
            .collect();
        let proposal = |poll: &VerifiedPoll, size: usize| {
            let records = std::iter::once(&organizer)
                .chain(&members[..size - 1])
                .map(|credential| {
                    Arc::new(VerifiedRegistration::for_roster(
                        RegistrationHeader {
                            username: normalize_username(b"Participant").unwrap(),
                            poll: poll.identity(),
                            runtime: poll.runtime(),
                            signing_public: *credential.signing_public(),
                            recipient_key_hash: [0; 64],

                            fhe_key_commitments: vec![
                                [7; 64];
                                crate::source_binding::fhe_key_families(poll)
                                    .len()
                            ],
                        },
                        [0; 64],
                    ))
                })
                .collect();
            RosterProposal::new(poll, records)
        };
        let largest = poll(20);
        for size in Profile::participant_range() {
            let profile = proposal(&largest, size).unwrap().profile();
            assert_eq!((profile.participants(), profile.options()), (size, 10));
        }
        for size in [2, 21] {
            assert!(matches!(proposal(&largest, size), Err(Error::Shape)));
        }
        // A roster above the poll's signed maximum is refused.
        for maximum in 3..20 {
            let poll = poll(maximum);
            assert!(proposal(&poll, maximum).is_ok());
            assert!(matches!(proposal(&poll, maximum + 1), Err(Error::Context)));
        }
        assert_eq!(Profile::participant_range(), 3..=20);
    }
}
