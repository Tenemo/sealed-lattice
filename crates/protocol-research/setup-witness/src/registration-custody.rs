use super::*;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};

const PLAIN_BYTES: usize = 4 + 2 * RECIPIENT_SECRET_SUPPORT;
pub const SEALED_BYTES: usize = PLAIN_BYTES + 16;

impl RegistrationKey {
    /// Seals one completed registration key with a fresh, single-use local key.
    /// The caller owns that wrapping key's confidential browser-local custody.
    pub fn seal_retained(&mut self, key: &[u8; 32], associated: &[u8]) -> Result<Vec<u8>, Error> {
        if self.sealed || associated.is_empty() || associated.len() > 2048 {
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
            sealed: true,
        };
        result.validate_retained()?;
        Ok(result)
    }
}

#[cfg(test)]
#[path = "registration-custody-tests.rs"]
mod tests;
