#[path = "ballot-authentication.rs"]
pub mod ballot_authentication;
#[path = "ballot-body.rs"]
pub mod ballot_body;
#[path = "contribution-authentication.rs"]
pub mod contribution_authentication;
#[path = "contribution-commitment.rs"]
pub mod contribution_commitment;
mod custody;
pub use custody::SigningPurpose;
pub mod foundation;
pub mod poll;
#[path = "publication-signing.rs"]
pub mod publication_signing;
pub mod registration;
#[path = "release-signing.rs"]
pub mod release_signing;
pub mod roster;
#[path = "roster-authentication.rs"]
pub mod roster_authentication;
#[path = "roster-input.rs"]
pub mod roster_input;
#[path = "target-signing.rs"]
pub mod target_signing;

use fips203::{
    ml_kem_768,
    traits::{KeyGen as KemKeyGen, SerDes as KemSerDes},
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use foundation::{
    CanonicalItem, RegistrationHeader, hash::StreamingFoundationTupleHash512,
    participant_identity::derive_participant_identity,
};
use zeroize::Zeroizing;

pub const SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/registration/v1";
pub const MAXIMUM_PROOF_BYTES: usize = 8_604_512;

#[derive(Debug)]
pub enum Error {
    Shape,
    Context,
    Consumed,
    Crypto,
}

pub struct Credential {
    signing_seed: Zeroizing<[u8; 32]>,
    signing_public: [u8; 1952],
    mailbox_public: [u8; 1184],
    signed: bool,
    completed_body: Option<[u8; 64]>,
    sealed: bool,
    poll_creation_consumed: bool,
    proposal_signed: bool,
    ballot_signed: bool,
    ballot_attempted: bool,
    ballot_close_signed: bool,
    slot_witness_signed: bool,
    target_signed: bool,
    target_lock: Option<[u8; 64]>,
    release_started: bool,
    release_signed: bool,
    confirmation: Option<contribution_authentication::ConfirmationLock>,
    locked_purposes: u16,
}
impl Credential {
    pub fn from_seeds(
        signing: [u8; 32],
        mailbox_first: [u8; 32],
        mailbox_second: [u8; 32],
    ) -> Self {
        let signing_seed = Zeroizing::new(signing);
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&signing_seed);
        drop(private);
        let (mailbox, private_mailbox) =
            ml_kem_768::KG::keygen_from_seed(mailbox_first, mailbox_second);
        drop(private_mailbox);
        Self {
            signing_seed,
            signing_public: public.into_bytes(),
            mailbox_public: mailbox.into_bytes(),
            signed: false,
            completed_body: None,
            sealed: false,
            poll_creation_consumed: false,
            proposal_signed: false,
            ballot_signed: false,
            ballot_attempted: false,
            ballot_close_signed: false,
            slot_witness_signed: false,
            target_signed: false,
            target_lock: None,
            release_started: false,
            release_signed: false,
            confirmation: None,
            locked_purposes: 0,
        }
    }
    pub fn signing_public(&self) -> &[u8; 1952] {
        &self.signing_public
    }
    pub fn mailbox_public(&self) -> &[u8; 1184] {
        &self.mailbox_public
    }
    pub fn proof_role(&self, poll: [u8; 64], runtime: [u8; 64]) -> Vec<u8> {
        registration_proof_role(poll, runtime, &self.signing_public)
    }
    pub fn sign_registration(
        &mut self,
        body: BodyDigest,
        randomness: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
        if self.signed {
            return Err(Error::Consumed);
        }
        if body.signing_public != self.signing_public || body.mailbox_public != self.mailbox_public
        {
            return Err(Error::Context);
        }
        self.signed = true;
        self.poll_creation_consumed = true;
        let coins = Zeroizing::new(randomness);
        let (_, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        let signature = private
            .try_sign_with_seed(&coins, &body.digest, SIGNATURE_CONTEXT)
            .map_err(|_| Error::Crypto)?;
        self.completed_body = Some(body.digest);
        Ok(signature)
    }

    pub fn check_retained(&self) -> bool {
        let (public, private) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        drop(private);
        public.into_bytes() == self.signing_public
    }
}

pub fn registration_proof_role(poll: [u8; 64], runtime: [u8; 64], public: &[u8; 1952]) -> Vec<u8> {
    let identity = derive_participant_identity(public).unwrap();
    let mut role = Vec::from(b"registered-recipient-key/1".as_slice());
    role.extend(poll);
    role.extend(runtime);
    role.extend(identity.to_lowercase_hex().as_bytes());
    role
}

pub struct BodyDigest {
    digest: [u8; 64],
    signing_public: [u8; 1952],
    mailbox_public: [u8; 1184],
}
impl BodyDigest {
    pub fn bytes(&self) -> [u8; 64] {
        self.digest
    }
}

pub struct BodyHasher {
    hash: Option<StreamingFoundationTupleHash512>,
    signing_public: [u8; 1952],
    mailbox_public: [u8; 1184],
}
impl BodyHasher {
    pub fn new(header: RegistrationHeader) -> Result<Self, Error> {
        if !(4004..=MAXIMUM_PROOF_BYTES).contains(&header.proof_length) {
            return Err(Error::Shape);
        }
        ml_dsa_65::PublicKey::try_from_bytes(header.signing_public).map_err(|_| Error::Shape)?;
        ml_kem_768::EncapsKey::try_from_bytes(header.mailbox_public).map_err(|_| Error::Shape)?;
        let encoded = header.encode()?;
        let prefix = [CanonicalItem::variable_bytes(encoded).map_err(|_| Error::Shape)?];
        let hash = StreamingFoundationTupleHash512::new_variable_bytes(
            "sealed-lattice/registration-body/v1",
            &prefix,
            header.proof_length,
        )
        .map_err(|_| Error::Shape)?;
        Ok(Self {
            hash: Some(hash),
            signing_public: header.signing_public,
            mailbox_public: header.mailbox_public,
        })
    }
    pub fn from_header(
        bytes: &[u8],
        expected_poll: [u8; 64],
        expected_runtime: [u8; 64],
    ) -> Result<(Self, usize), Error> {
        let (header, consumed) = RegistrationHeader::decode_prefix(bytes)?;
        if header.poll != expected_poll || header.runtime != expected_runtime {
            return Err(Error::Context);
        }
        Ok((Self::new(header)?, consumed))
    }
    pub fn absorb(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let Some(mut hash) = self.hash.take() else {
            return Err(Error::Consumed);
        };
        if bytes.len() > 1 << 20 {
            return Err(Error::Shape);
        }
        hash.absorb(bytes).map_err(|_| Error::Shape)?;
        self.hash = Some(hash);
        Ok(())
    }
    pub fn finish(mut self) -> Result<BodyDigest, Error> {
        let digest = self
            .hash
            .take()
            .ok_or(Error::Consumed)?
            .finalize()
            .map_err(|_| Error::Shape)?
            .into_bytes();
        Ok(BodyDigest {
            digest,
            signing_public: self.signing_public,
            mailbox_public: self.mailbox_public,
        })
    }
}

pub fn verify_registration_signature(body: BodyDigest, signature: &[u8]) -> bool {
    let Ok(signature) = signature.try_into() else {
        return false;
    };
    let Ok(public) = ml_dsa_65::PublicKey::try_from_bytes(body.signing_public) else {
        return false;
    };
    public.verify(&body.digest, &signature, SIGNATURE_CONTEXT)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn body(credential: &Credential, poll: [u8; 64]) -> BodyDigest {
        let mut hasher = BodyHasher::new(RegistrationHeader {
            username: foundation::normalize_username(b"Participant").unwrap(),
            poll,
            runtime: [2; 64],
            signing_public: *credential.signing_public(),
            mailbox_public: *credential.mailbox_public(),
            recipient_key_hash: [3; 64],
            proof_length: 5000,
        })
        .unwrap();
        hasher.absorb(&[4; 4999]).unwrap();
        hasher.absorb(&[5]).unwrap();
        hasher.finish().unwrap()
    }
    #[test]
    fn credentials_sign_one_body_and_bind_the_full_public_context() {
        let mut credential = Credential::from_seeds([7; 32], [8; 32], [9; 32]);
        let signature = credential
            .sign_registration(body(&credential, [1; 64]), [10; 32])
            .unwrap();
        assert!(verify_registration_signature(
            body(&credential, [1; 64]),
            &signature
        ));
        assert!(!verify_registration_signature(
            body(&credential, [2; 64]),
            &signature
        ));
        assert!(!verify_registration_signature(
            body(&credential, [1; 64]),
            &signature[..3308]
        ));
        assert!(
            credential
                .sign_registration(body(&credential, [1; 64]), [11; 32])
                .is_err()
        );
    }
    #[test]
    fn body_streams_refuse_incomplete_or_ignored_overrun_requests() {
        let credential = Credential::from_seeds([7; 32], [8; 32], [9; 32]);
        let make = || {
            BodyHasher::new(RegistrationHeader {
                username: foundation::normalize_username(b"Participant").unwrap(),
                poll: [1; 64],
                runtime: [2; 64],
                signing_public: *credential.signing_public(),
                mailbox_public: *credential.mailbox_public(),
                recipient_key_hash: [3; 64],
                proof_length: 5000,
            })
            .unwrap()
        };
        let mut incomplete = make();
        incomplete.absorb(&[0; 4999]).unwrap();
        assert!(incomplete.finish().is_err());
        let mut overrun = make();
        assert!(overrun.absorb(&[0; 5001]).is_err());
        assert!(overrun.absorb(&[0; 5000]).is_err());
        assert!(overrun.finish().is_err());
    }
    #[test]
    fn canonical_header_prefixes_bind_context_and_delimit_the_proof() {
        let credential = Credential::from_seeds([7; 32], [8; 32], [9; 32]);
        let header = RegistrationHeader {
            username: foundation::normalize_username(b"Participant").unwrap(),
            poll: [1; 64],
            runtime: [2; 64],
            signing_public: *credential.signing_public(),
            mailbox_public: *credential.mailbox_public(),
            recipient_key_hash: [3; 64],
            proof_length: 5000,
        }
        .encode()
        .unwrap();
        let mut combined = header.clone();
        combined.extend([4; 128]);
        let (mut decoded, consumed) = BodyHasher::from_header(&combined, [1; 64], [2; 64]).unwrap();
        assert_eq!(consumed, header.len());
        decoded.absorb(&[4; 4999]).unwrap();
        decoded.absorb(&[5]).unwrap();
        assert_eq!(
            decoded.finish().unwrap().bytes(),
            body(&credential, [1; 64]).bytes()
        );
        assert!(BodyHasher::from_header(&header, [9; 64], [2; 64]).is_err());
        let mut altered = header.clone();
        altered[2] = 2;
        assert!(BodyHasher::from_header(&altered, [1; 64], [2; 64]).is_err());
        assert!(BodyHasher::from_header(&header[..header.len() - 1], [1; 64], [2; 64]).is_err());
    }

    #[test]
    fn signed_usernames_are_canonical_bounded_and_not_replaceable() {
        let mut credential = Credential::from_seeds([7; 32], [8; 32], [9; 32]);
        let make = |name: &[u8]| RegistrationHeader {
            username: foundation::normalize_username(name).unwrap(),
            poll: [1; 64],
            runtime: [2; 64],
            signing_public: *credential.signing_public(),
            mailbox_public: *credential.mailbox_public(),
            recipient_key_hash: [3; 64],
            proof_length: 5000,
        };
        let original = make(b"Jose\xcc\x81");
        assert_eq!(original.username.as_str(), "Jos\u{e9}");
        let encoded = original.encode().unwrap();
        let mut changed = make(b"Other");
        let other = changed.encode().unwrap();
        changed.username = foundation::normalize_username(&[b'n'; 128]).unwrap();
        assert!(changed.encode().is_ok());
        assert!(foundation::normalize_username(&[b'n'; 129]).is_err());
        assert!(foundation::normalize_username(b"").is_err());
        assert!(foundation::normalize_username(&[0xff]).is_err());
        let hash = |header: &[u8]| {
            let (mut value, _) = BodyHasher::from_header(header, [1; 64], [2; 64]).unwrap();
            value.absorb(&[4; 5000]).unwrap();
            value.finish().unwrap()
        };
        let signature = credential
            .sign_registration(hash(&encoded), [10; 32])
            .unwrap();
        assert!(verify_registration_signature(hash(&encoded), &signature));
        assert!(!verify_registration_signature(hash(&other), &signature));
        let mut noncanonical = encoded[..encoded.len() - 15].to_vec();
        noncanonical.extend(12u16.to_le_bytes());
        noncanonical.extend(10u32.to_le_bytes());
        noncanonical.extend(6u32.to_le_bytes());
        noncanonical.extend(b"Jose\xcc\x81");
        assert!(BodyHasher::from_header(&noncanonical, [1; 64], [2; 64]).is_err());
    }
}
