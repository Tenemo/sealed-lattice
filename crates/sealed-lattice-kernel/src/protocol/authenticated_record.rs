use core::fmt;

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce, Tag,
    aead::{AeadInPlace, KeyInit},
};
use zeroize::Zeroize;

pub const KEY_BYTE_LENGTH: usize = 32;
pub const ASSOCIATED_DATA_BYTE_LENGTH: usize = 356;
pub const PLAINTEXT_BYTE_LENGTH: usize = 6_734;
pub const TAG_BYTE_LENGTH: usize = 16;
pub const SEALED_RECORD_BYTE_LENGTH: usize = PLAINTEXT_BYTE_LENGTH + TAG_BYTE_LENGTH;

const ONE_RECORD_NONCE: [u8; 12] = [0_u8; 12];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticatedRecordError {
    AuthenticationFailed,
    InvalidAssociatedDataLength,
    InvalidKeyLength,
    InvalidPlaintextLength,
    InvalidSealedRecordLength,
}

impl fmt::Display for AuthenticatedRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthenticationFailed => "private record authentication failed",
            Self::InvalidAssociatedDataLength => {
                "private record associated data has the wrong length"
            }
            Self::InvalidKeyLength => "private record key has the wrong length",
            Self::InvalidPlaintextLength => "private record plaintext has the wrong length",
            Self::InvalidSealedRecordLength => "private record has the wrong length",
        })
    }
}

impl std::error::Error for AuthenticatedRecordError {}

pub fn seal(
    key: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AuthenticatedRecordError> {
    require_lengths(key, associated_data)?;
    if plaintext.len() != PLAINTEXT_BYTE_LENGTH {
        return Err(AuthenticatedRecordError::InvalidPlaintextLength);
    }
    seal_with_nonce(key, &ONE_RECORD_NONCE, associated_data, plaintext)
}

pub fn open(
    key: &[u8],
    associated_data: &[u8],
    sealed_record: &[u8],
) -> Result<Vec<u8>, AuthenticatedRecordError> {
    require_lengths(key, associated_data)?;
    if sealed_record.len() != SEALED_RECORD_BYTE_LENGTH {
        return Err(AuthenticatedRecordError::InvalidSealedRecordLength);
    }
    open_with_nonce(key, &ONE_RECORD_NONCE, associated_data, sealed_record)
}

fn require_lengths(key: &[u8], associated_data: &[u8]) -> Result<(), AuthenticatedRecordError> {
    if key.len() != KEY_BYTE_LENGTH {
        return Err(AuthenticatedRecordError::InvalidKeyLength);
    }
    if associated_data.len() != ASSOCIATED_DATA_BYTE_LENGTH {
        return Err(AuthenticatedRecordError::InvalidAssociatedDataLength);
    }
    Ok(())
}

fn seal_with_nonce(
    key: &[u8],
    nonce: &[u8; 12],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AuthenticatedRecordError> {
    if key.len() != KEY_BYTE_LENGTH {
        return Err(AuthenticatedRecordError::InvalidKeyLength);
    }
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| AuthenticatedRecordError::InvalidKeyLength)?;
    let mut record = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), associated_data, &mut record)
        .map_err(|_| AuthenticatedRecordError::AuthenticationFailed)?;
    record.extend_from_slice(&tag);
    Ok(record)
}

fn open_with_nonce(
    key: &[u8],
    nonce: &[u8; 12],
    associated_data: &[u8],
    sealed_record: &[u8],
) -> Result<Vec<u8>, AuthenticatedRecordError> {
    if key.len() != KEY_BYTE_LENGTH || sealed_record.len() < TAG_BYTE_LENGTH {
        return Err(if key.len() != KEY_BYTE_LENGTH {
            AuthenticatedRecordError::InvalidKeyLength
        } else {
            AuthenticatedRecordError::InvalidSealedRecordLength
        });
    }
    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| AuthenticatedRecordError::InvalidKeyLength)?;
    let (ciphertext, tag_bytes) = sealed_record.split_at(sealed_record.len() - TAG_BYTE_LENGTH);
    let mut plaintext = ciphertext.to_vec();
    let tag = Tag::from_slice(tag_bytes);
    if cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(nonce),
            associated_data,
            &mut plaintext,
            tag,
        )
        .is_err()
    {
        plaintext.zeroize();
        return Err(AuthenticatedRecordError::AuthenticationFailed);
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const BYTE_LENGTH: usize>(hex: &str) -> [u8; BYTE_LENGTH] {
        assert_eq!(hex.len(), 2 * BYTE_LENGTH);
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).expect("valid hex")
        })
    }

    #[test]
    fn matches_rfc_8452_aes_256_vector_with_associated_data() {
        let key =
            decode_hex::<32>("0100000000000000000000000000000000000000000000000000000000000000");
        let nonce = decode_hex::<12>("030000000000000000000000");
        let associated_data = decode_hex::<1>("01");
        let plaintext = decode_hex::<8>("0200000000000000");
        let expected = decode_hex::<24>("1de22967237a813291213f267e3b452f02d01ae33e4ec854");

        let sealed = seal_with_nonce(&key, &nonce, &associated_data, &plaintext)
            .expect("RFC 8452 vector seals");
        assert_eq!(sealed, expected);
        assert_eq!(
            open_with_nonce(&key, &nonce, &associated_data, &sealed)
                .expect("RFC 8452 vector opens"),
            plaintext
        );
    }

    #[test]
    fn exact_record_round_trip_and_mutations() {
        let key = [0x31_u8; KEY_BYTE_LENGTH];
        let associated_data = [0x52_u8; ASSOCIATED_DATA_BYTE_LENGTH];
        let plaintext = (0..PLAINTEXT_BYTE_LENGTH)
            .map(|index| ((index * 37 + 11) % 251) as u8)
            .collect::<Vec<_>>();
        let sealed = seal(&key, &associated_data, &plaintext).expect("record seals");
        assert_eq!(sealed.len(), SEALED_RECORD_BYTE_LENGTH);
        assert_eq!(
            open(&key, &associated_data, &sealed).expect("record opens"),
            plaintext
        );

        for mutation_index in [0, PLAINTEXT_BYTE_LENGTH - 1, SEALED_RECORD_BYTE_LENGTH - 1] {
            let mut mutated = sealed.clone();
            mutated[mutation_index] ^= 1;
            assert_eq!(
                open(&key, &associated_data, &mutated),
                Err(AuthenticatedRecordError::AuthenticationFailed)
            );
        }

        let mut wrong_associated_data = associated_data;
        wrong_associated_data[0] ^= 1;
        assert_eq!(
            open(&key, &wrong_associated_data, &sealed),
            Err(AuthenticatedRecordError::AuthenticationFailed)
        );

        let mut wrong_key = key;
        wrong_key[31] ^= 1;
        assert_eq!(
            open(&wrong_key, &associated_data, &sealed),
            Err(AuthenticatedRecordError::AuthenticationFailed)
        );
    }

    #[test]
    fn exact_record_lengths_are_enforced() {
        let key = [0_u8; KEY_BYTE_LENGTH];
        let associated_data = [0_u8; ASSOCIATED_DATA_BYTE_LENGTH];
        let plaintext = [0_u8; PLAINTEXT_BYTE_LENGTH];
        let sealed = [0_u8; SEALED_RECORD_BYTE_LENGTH];

        assert_eq!(
            seal(&key[..31], &associated_data, &plaintext),
            Err(AuthenticatedRecordError::InvalidKeyLength)
        );
        assert_eq!(
            seal(&key, &associated_data[..355], &plaintext),
            Err(AuthenticatedRecordError::InvalidAssociatedDataLength)
        );
        assert_eq!(
            seal(
                &key,
                &associated_data,
                &plaintext[..PLAINTEXT_BYTE_LENGTH - 1]
            ),
            Err(AuthenticatedRecordError::InvalidPlaintextLength)
        );
        assert_eq!(
            open(
                &key,
                &associated_data,
                &sealed[..SEALED_RECORD_BYTE_LENGTH - 1]
            ),
            Err(AuthenticatedRecordError::InvalidSealedRecordLength)
        );
    }
}
