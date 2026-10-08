use super::*;
use parallel_work::sealing::{self, Sealed, TAG_BYTES};

const PLAIN_BYTES: usize = 4 + 2 * RECIPIENT_SECRET_SUPPORT;
pub const SEALED_BYTES: usize = PLAIN_BYTES + TAG_BYTES;

impl RegistrationKey {
    /// Seals one completed registration key under a fresh, single-use local
    /// key. The caller owns that key's confidential browser-local custody.
    pub fn seal_retained(&mut self, associated: &[u8]) -> Result<Sealed, Error> {
        if self.sealed || associated.is_empty() || associated.len() > 2048 {
            return Err(Error::Consumed);
        }
        self.sealed = true;
        self.validate_retained()?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(PLAIN_BYTES));
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
        Ok(sealing::seal(&bytes, associated))
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
        let bytes = sealing::open(key, associated, sealed).ok_or(Error::InvalidState)?;
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
