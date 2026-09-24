use crate::{Credential, Error};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use fips203::{ml_kem_768, traits::SerDes as KemSerDes};
use zeroize::Zeroizing;

const SEALED_BYTES: usize = 4 + 32 + 16;

/// Signing purposes that a restored credential withholds until the
/// authenticated participant root unlocks those its records show unused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigningPurpose {
    Proposal,
    Confirmation,
    Opening,
    Ballot,
    CloseIntent,
    CloseResponse,
    CloseProposal,
    Target,
    Release,
}
impl SigningPurpose {
    pub const fn mask(self) -> u16 {
        1 << self as u16
    }
}
const ALL_SIGNING_PURPOSES: u16 = (SigningPurpose::Release.mask() << 1) - 1;

fn associated(body: [u8; 64]) -> Vec<u8> {
    let mut bytes = Vec::from(b"registration-signing-seed/1".as_slice());
    bytes.extend(body);
    bytes
}

impl Credential {
    pub fn seal_complete(&mut self, key: &[u8; 32]) -> Result<Vec<u8>, Error> {
        if self.sealed {
            return Err(Error::Consumed);
        }
        let body = self.completed_body.ok_or(Error::Consumed)?;
        self.sealed = true;
        if !self.check_retained() {
            return Err(Error::Crypto);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(SEALED_BYTES));
        bytes.extend(b"RCS1");
        bytes.extend(*self.signing_seed);
        Aes256Gcm::new(key.into())
            .encrypt_in_place(Nonce::from_slice(&[0; 12]), &associated(body), &mut *bytes)
            .map_err(|_| Error::Crypto)?;
        Ok(std::mem::take(&mut *bytes))
    }
    pub fn open_complete(
        signing_public: [u8; 1952],
        mailbox_public: [u8; 1184],
        body: [u8; 64],
        key: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Self, Error> {
        if sealed.len() != SEALED_BYTES {
            return Err(Error::Shape);
        }
        ml_kem_768::EncapsKey::try_from_bytes(mailbox_public).map_err(|_| Error::Shape)?;
        let mut bytes = Zeroizing::new(sealed.to_vec());
        Aes256Gcm::new(key.into())
            .decrypt_in_place(Nonce::from_slice(&[0; 12]), &associated(body), &mut *bytes)
            .map_err(|_| Error::Crypto)?;
        if bytes.len() != 36 || &bytes[..4] != b"RCS1" {
            return Err(Error::Shape);
        }
        let value = Self {
            signing_seed: Zeroizing::new(bytes[4..].try_into().map_err(|_| Error::Shape)?),
            signing_public,
            mailbox_public,
            signed: true,
            completed_body: Some(body),
            sealed: true,
            poll_creation_consumed: true,
            proposal_signed: false,
            signed_ballot: None,
            ballot_attempted: false,
            close_intent_signed: false,
            close_lock: None,
            close_response: None,
            close_proposal_signed: false,
            target_signed: false,
            target_lock: None,
            release_started: false,
            release_signed: false,
            confirmation: None,
            locked_purposes: ALL_SIGNING_PURPOSES,
        };
        if !value.check_retained() {
            return Err(Error::Crypto);
        }
        Ok(value)
    }
    /// Unlocks the purposes that the authenticated participant root has shown
    /// unused. Completed messages are restored from their verified records
    /// instead, so a purpose left locked signs nothing new.
    pub fn unlock_unused_purposes(&mut self, mask: u16) -> Result<(), Error> {
        if mask & !ALL_SIGNING_PURPOSES != 0 {
            return Err(Error::Shape);
        }
        self.locked_purposes &= !mask;
        Ok(())
    }
    pub(crate) fn check_unlocked(&self, purpose: SigningPurpose) -> Result<(), Error> {
        if self.locked_purposes & purpose.mask() != 0 {
            return Err(Error::Consumed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BodyHasher,
        foundation::{RegistrationHeader, normalize_username},
    };
    #[test]
    fn restored_signing_keys_cannot_recreate_authority_the_root_does_not_unlock() {
        let mut original = Credential::from_seeds([7; 32], [8; 32], [9; 32]);
        let data_key = [11; 32];
        assert!(original.seal_complete(&data_key).is_err());
        let make = || {
            let mut hash = BodyHasher::new(RegistrationHeader {
                username: normalize_username(b"Participant").unwrap(),
                poll: [1; 64],
                runtime: [2; 64],
                signing_public: *original.signing_public(),
                mailbox_public: *original.mailbox_public(),
                recipient_key_hash: [3; 64],
                proof_length: 5000,
            })
            .unwrap();
            hash.absorb(&[4; 5000]).unwrap();
            hash.finish().unwrap()
        };
        let digest = make();
        let body = digest.bytes();
        let for_repeat = make();
        original.sign_registration(digest, [10; 32]).unwrap();
        let sealed = original.seal_complete(&data_key).unwrap();
        assert_eq!(sealed.len(), SEALED_BYTES);
        assert!(original.seal_complete(&data_key).is_err());
        let mut restored = Credential::open_complete(
            *original.signing_public(),
            *original.mailbox_public(),
            body,
            &data_key,
            &sealed,
        )
        .unwrap();
        assert!(restored.check_retained());
        assert!(restored.sign_registration(for_repeat, [12; 32]).is_err());
        assert!(restored.seal_complete(&data_key).is_err());
        let purposes = [
            SigningPurpose::Proposal,
            SigningPurpose::Confirmation,
            SigningPurpose::Opening,
            SigningPurpose::Ballot,
            SigningPurpose::CloseIntent,
            SigningPurpose::CloseResponse,
            SigningPurpose::CloseProposal,
            SigningPurpose::Target,
            SigningPurpose::Release,
        ];
        for purpose in purposes {
            assert!(original.check_unlocked(purpose).is_ok());
            assert!(matches!(
                restored.check_unlocked(purpose),
                Err(Error::Consumed)
            ));
        }
        for undefined in [1 << 9, u16::MAX] {
            assert!(matches!(
                restored.unlock_unused_purposes(undefined),
                Err(Error::Shape)
            ));
        }
        restored.unlock_unused_purposes(0).unwrap();
        restored
            .unlock_unused_purposes(
                SigningPurpose::Ballot.mask() | SigningPurpose::CloseResponse.mask(),
            )
            .unwrap();
        for purpose in purposes {
            assert_eq!(
                restored.check_unlocked(purpose).is_ok(),
                matches!(
                    purpose,
                    SigningPurpose::Ballot | SigningPurpose::CloseResponse
                )
            );
        }
        let mut changed = sealed.clone();
        changed[20] ^= 1;
        assert!(
            Credential::open_complete(
                *original.signing_public(),
                *original.mailbox_public(),
                body,
                &data_key,
                &changed
            )
            .is_err()
        );
        let mut wrong_seed = Vec::from(b"RCS1".as_slice());
        wrong_seed.extend([6u8; 32]);
        Aes256Gcm::new((&data_key).into())
            .encrypt_in_place(
                Nonce::from_slice(&[0; 12]),
                &associated(body),
                &mut wrong_seed,
            )
            .unwrap();
        assert!(
            Credential::open_complete(
                *original.signing_public(),
                *original.mailbox_public(),
                body,
                &data_key,
                &wrong_seed
            )
            .is_err()
        );
        let mut extra = sealed.clone();
        extra.push(0);
        assert!(
            Credential::open_complete(
                *original.signing_public(),
                *original.mailbox_public(),
                body,
                &data_key,
                &extra
            )
            .is_err()
        );
        assert!(
            Credential::open_complete(
                *original.signing_public(),
                *original.mailbox_public(),
                [0; 64],
                &data_key,
                &sealed
            )
            .is_err()
        );
    }
}
