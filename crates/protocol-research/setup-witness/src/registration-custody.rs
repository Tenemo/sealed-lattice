use super::*;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};

const PLAIN_BYTES: usize = 4 + 2 * 256;
pub const SEALED_BYTES: usize = PLAIN_BYTES + 16;

impl RegistrationKey {
    /// Seals one completed registration key with a fresh, single-use local key.
    /// The caller owns that wrapping key's confidential browser-local custody.
    pub fn seal_retained(&mut self, key: &[u8; 32], associated: &[u8]) -> Result<Vec<u8>, Error> {
        if self.sealed
            || self.proof_words.is_some()
            || associated.is_empty()
            || associated.len() > 2048
        {
            return Err(Error::Consumed);
        }
        self.sealed = true;
        self.validate_retained()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(SEALED_BYTES));
        bytes.extend(b"RKC1");
        for sign in [1i8, -1] {
            for (position, value) in self.secret.iter().enumerate() {
                if *value == sign {
                    bytes.extend((position as u16).to_le_bytes());
                }
            }
        }
        if bytes.len() != PLAIN_BYTES {
            return Err(Error::InvalidState);
        }
        Aes256Gcm::new(key.into())
            .encrypt_in_place(Nonce::from_slice(&[0; 12]), associated, &mut *bytes)
            .map_err(|_| Error::InvalidState)?;
        Ok(std::mem::take(&mut *bytes))
    }

    pub fn open_retained(
        public: Vec<BigInt>,
        key: &[u8; 32],
        associated: &[u8],
        sealed: &[u8],
    ) -> Result<Self, Error> {
        if sealed.len() != SEALED_BYTES
            || associated.is_empty()
            || associated.len() > 2048
            || public.len() != DEGREE
        {
            return Err(Error::InvalidState);
        }
        let mut bytes = Zeroizing::new(sealed.to_vec());
        Aes256Gcm::new(key.into())
            .decrypt_in_place(Nonce::from_slice(&[0; 12]), associated, &mut *bytes)
            .map_err(|_| Error::InvalidState)?;
        if bytes.len() != PLAIN_BYTES || &bytes[..4] != b"RKC1" {
            return Err(Error::InvalidState);
        }
        let mut secret = Zeroizing::new(vec![0i8; DEGREE]);
        for (group, sign) in [1i8, -1].into_iter().enumerate() {
            let mut previous = None;
            for index in 0..128 {
                let offset = 4 + 2 * (group * 128 + index);
                let position = usize::from(u16::from_le_bytes(
                    bytes[offset..offset + 2].try_into().unwrap(),
                ));
                if previous.is_some_and(|old| old >= position) || secret[position] != 0 {
                    return Err(Error::InvalidState);
                }
                secret[position] = sign;
                previous = Some(position);
            }
        }
        let result = Self {
            public,
            secret,
            proof_words: None,
            sealed: true,
        };
        result.validate_retained()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sealed_keys_restore_once_without_restoring_proof_or_resealing_authority() {
        let mut original = RegistrationKey::new();
        let key = [7; 32];
        assert!(
            original
                .seal_retained(&key, b"registration/context")
                .is_err()
        );
        original.take_proof_columns().unwrap();
        let sealed = original
            .seal_retained(&key, b"registration/context")
            .unwrap();
        assert_eq!(sealed.len(), SEALED_BYTES);
        assert!(
            original
                .seal_retained(&key, b"registration/context")
                .is_err()
        );
        let mut restored = RegistrationKey::open_retained(
            original.public.clone(),
            &key,
            b"registration/context",
            &sealed,
        )
        .unwrap();
        assert_eq!(*original.secret, *restored.secret);
        assert!(restored.take_proof_columns().is_err());
        assert!(
            restored
                .seal_retained(&key, b"registration/context")
                .is_err()
        );
        let mut changed = sealed.clone();
        changed[32] ^= 1;
        assert!(
            RegistrationKey::open_retained(
                original.public.clone(),
                &key,
                b"registration/context",
                &changed
            )
            .is_err()
        );
        assert!(
            RegistrationKey::open_retained(
                original.public.clone(),
                &key,
                b"other/context",
                &sealed
            )
            .is_err()
        );
        assert!(
            RegistrationKey::open_retained(
                original.public.clone(),
                &[8; 32],
                b"registration/context",
                &sealed
            )
            .is_err()
        );
        assert!(
            RegistrationKey::open_retained(
                original.public.clone(),
                &key,
                b"registration/context",
                &sealed[..SEALED_BYTES - 1]
            )
            .is_err()
        );
        let mut changed_public = original.public.clone();
        changed_public[0] += 1024;
        assert!(
            RegistrationKey::open_retained(changed_public, &key, b"registration/context", &sealed)
                .is_err()
        );
    }
}
