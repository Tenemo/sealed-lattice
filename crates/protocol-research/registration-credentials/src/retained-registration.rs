//! The participant's own registration, which its registration verifier
//! accepted, retained beneath the participant root and keyed to the
//! credential the header names. A later visit of the same participant
//! restores the verifier's result from the header and the key alone: the
//! header must be the one the verifier accepted and the key must hash to the
//! value that header names, so the proof is neither read nor verified again.
use super::{RegistrationVerifier, VerifiedRegistration};
use crate::{
    Credential, Error, RETAINED_TAG_BYTES, foundation::RegistrationHeader, poll::VerifiedPoll,
};

const LABEL: &[u8] = b"sealed-lattice/retained-registration/v1";

/// A retained registration: the proof hash, the body digest and the tag.
pub const RETAINED_REGISTRATION_BYTES: usize = 64 + 64 + RETAINED_TAG_BYTES;

// The bytes the tag covers: the length-prefixed canonical header, then the
// proof hash and the body digest.
fn tagged_bytes(header: &RegistrationHeader, digests: &[u8]) -> Result<Vec<u8>, Error> {
    let header = header.encode()?;
    Ok([
        (header.len() as u32).to_le_bytes().as_slice(),
        &header,
        digests,
    ]
    .concat())
}

// The credential must be the one the header names, for the header's poll.
fn check_owner(
    credential: &Credential,
    poll: &VerifiedPoll,
    header: &RegistrationHeader,
) -> Result<(), Error> {
    if credential.signing_public() != &header.signing_public
        || poll.identity() != header.poll
        || poll.runtime() != header.runtime
    {
        return Err(Error::Context);
    }
    Ok(())
}

impl VerifiedRegistration {
    /// Keys the participant's own registration, as its verifier accepted
    /// it, to the credential the header names.
    pub fn retain(&self, credential: &Credential, poll: &VerifiedPoll) -> Result<Vec<u8>, Error> {
        check_owner(credential, poll, &self.header)?;
        let digests = [self.proof_hash, self.body_digest].concat();
        let tag = credential.retained_tag(LABEL, poll, &tagged_bytes(&self.header, &digests)?);
        Ok([digests.as_slice(), &tag].concat())
    }
}

impl RegistrationVerifier {
    /// Restores the participant's own registration from its retained copy
    /// in place of the proof, once the key its header names has arrived.
    /// Only the credential that retained it restores it.
    pub fn restore(
        self,
        credential: &Credential,
        poll: &VerifiedPoll,
        retained: &[u8],
    ) -> Result<VerifiedRegistration, Error> {
        if self.failed || !self.key_finished || !self.proof_prefix.is_empty() {
            return Err(Error::Consumed);
        }
        if retained.len() != RETAINED_REGISTRATION_BYTES {
            return Err(Error::Shape);
        }
        check_owner(credential, poll, &self.header)?;
        let (digests, tag) = retained.split_at(128);
        credential.check_retained_tag(LABEL, poll, &tagged_bytes(&self.header, digests)?, tag)?;
        Ok(VerifiedRegistration {
            header: self.header,
            body_digest: digests[64..].try_into().unwrap(),
            proof_hash: digests[..64].try_into().unwrap(),
            public_key: self.key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        SIGNATURE_BYTES,
        foundation::{
            StabilizedDisplayText,
            ceremony::{Manifest, OptionDefinition},
            normalize_username,
        },
        poll::{PollDraft, verify_poll},
        registration::KEY_BYTES,
    };
    use parallel_work::{Digest, ProtocolHash};
    use registration_verifier::CHUNK_LIMIT;

    use supported_profile::relation::PROOF_HEADER_BYTES;

    struct Registration {
        poll: VerifiedPoll,
        credential: Credential,
        header: Vec<u8>,
        key: Vec<u8>,
        verified: VerifiedRegistration,
    }

    // A member's registration of an organizer's poll under the runtime,
    // with a key whose hash its header names, as its verifier accepted it.
    fn registration(runtime: [u8; 64], seed: u8) -> Registration {
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
            PollDraft::new(Manifest::new(text("Question"), options).unwrap(), 2, 10).unwrap();
        let mut organizer = Credential::from_seeds([1; 32], [2; 32], [3; 32]);
        let packet = organizer
            .create_poll(draft, runtime, [5; 32], [6; 32])
            .unwrap();
        let poll = verify_poll(packet.identity, runtime, &packet.body, &packet.signature).unwrap();
        let credential = Credential::from_seeds([seed; 32], [seed + 10; 32], [seed + 20; 32]);
        let key: Vec<u8> = (0..KEY_BYTES).map(|index| (index as u8) ^ seed).collect();
        let header = RegistrationHeader {
            username: normalize_username(b"Participant").unwrap(),
            poll: poll.identity(),
            runtime,
            signing_public: *credential.signing_public(),
            mailbox_public: *credential.mailbox_public(),
            recipient_key_hash: ProtocolHash::digest(&key).into(),
            proof_length: PROOF_HEADER_BYTES + 1,
        };
        Registration {
            header: header.encode().unwrap(),
            verified: VerifiedRegistration::restored(
                header,
                [seed + 30; 64],
                [seed + 40; 64],
                key.clone(),
            ),
            poll,
            credential,
            key,
        }
    }

    // A verifier of the header that has taken the key, as the host streams
    // them before the retained copy.
    fn keyed(poll: &VerifiedPoll, header: &[u8], key: &[u8]) -> RegistrationVerifier {
        let mut verifier = RegistrationVerifier::new(poll, header, &[0; SIGNATURE_BYTES]).unwrap();
        for part in key.chunks(CHUNK_LIMIT) {
            verifier.push_key(part).unwrap();
        }
        verifier.finish_key().unwrap();
        verifier
    }

    // The restored registration is the verified one, from the header and
    // the key alone.
    #[test]
    fn retained_registrations_restore_the_verified_registration() {
        let registration = registration([4; 64], 7);
        let retained = registration
            .verified
            .retain(&registration.credential, &registration.poll)
            .unwrap();
        assert_eq!(retained.len(), RETAINED_REGISTRATION_BYTES);
        let restored = keyed(&registration.poll, &registration.header, &registration.key)
            .restore(&registration.credential, &registration.poll, &retained)
            .unwrap();
        assert_eq!(restored.header().encode().unwrap(), registration.header);
        assert_eq!(restored.body_digest(), registration.verified.body_digest());
        assert_eq!(restored.proof_hash(), registration.verified.proof_hash());
        assert_eq!(restored.public_key(), registration.key);
    }

    // Only the credential the header names retains the registration, and
    // only it restores the exact retained bytes, for the same poll and
    // runtime, the same header and the key that header names.
    #[test]
    fn retained_registrations_bind_the_credential_poll_header_and_exact_bytes() {
        let registration = registration([4; 64], 7);
        let (poll, credential) = (&registration.poll, &registration.credential);
        let retained = registration.verified.retain(credential, poll).unwrap();
        let refused = |credential: &Credential, poll: &VerifiedPoll, retained: &[u8]| {
            keyed(poll, &registration.header, &registration.key)
                .restore(credential, poll, retained)
                .is_err()
        };
        assert!(!refused(credential, poll, &retained));
        // Another credential, and one that shares every seed but the
        // signing seed.
        let other = Credential::from_seeds([8; 32], [18; 32], [28; 32]);
        assert!(registration.verified.retain(&other, poll).is_err());
        assert!(refused(&other, poll, &retained));
        let resealed = Credential::from_seeds([9; 32], [17; 32], [27; 32]);
        assert!(registration.verified.retain(&resealed, poll).is_err());
        assert!(refused(&resealed, poll, &retained));
        // The same member's registration under a poll of another runtime.
        let foreign = super::tests::registration([5; 64], 7);
        assert!(
            registration
                .verified
                .retain(&foreign.credential, &foreign.poll)
                .is_err()
        );
        assert!(
            keyed(&foreign.poll, &foreign.header, &foreign.key)
                .restore(&foreign.credential, &foreign.poll, &retained)
                .is_err()
        );
        // Another header of the same credential and key.
        let mut header = RegistrationHeader::decode_prefix(&registration.header)
            .unwrap()
            .0;
        header.username = normalize_username(b"Another participant").unwrap();
        assert!(
            keyed(poll, &header.encode().unwrap(), &registration.key)
                .restore(credential, poll, &retained)
                .is_err()
        );
        // Every changed, missing or extra byte.
        for position in [0, 63, 64, 127, 128, retained.len() - 1] {
            let mut changed = retained.clone();
            changed[position] ^= 1;
            assert!(refused(credential, poll, &changed), "{position}");
        }
        assert!(refused(credential, poll, &retained[..retained.len() - 1]));
        assert!(refused(
            credential,
            poll,
            &[retained.as_slice(), &[0]].concat()
        ));
    }

    // The retained copy replaces the proof only after the exact key the
    // header names, and never after proof bytes.
    #[test]
    fn restored_registrations_need_the_named_key_and_no_proof() {
        let registration = registration([4; 64], 7);
        let (poll, credential) = (&registration.poll, &registration.credential);
        let retained = registration.verified.retain(credential, poll).unwrap();
        let verifier = || {
            RegistrationVerifier::new(poll, &registration.header, &[0; SIGNATURE_BYTES]).unwrap()
        };
        // Before the key, and after a key with one changed byte.
        assert!(matches!(
            verifier().restore(credential, poll, &retained),
            Err(Error::Consumed)
        ));
        let mut changed = verifier();
        let mut key = registration.key.clone();
        key[KEY_BYTES / 2] ^= 1;
        for part in key.chunks(CHUNK_LIMIT) {
            changed.push_key(part).unwrap();
        }
        assert!(changed.finish_key().is_err());
        assert!(matches!(
            changed.restore(credential, poll, &retained),
            Err(Error::Consumed)
        ));
        // After proof bytes.
        let mut proved = keyed(poll, &registration.header, &registration.key);
        proved.push_proof(&[0; 16]).unwrap();
        assert!(matches!(
            proved.restore(credential, poll, &retained),
            Err(Error::Consumed)
        ));
    }
}
