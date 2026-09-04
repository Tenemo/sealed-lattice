use core::fmt;

use fips203::{
    ml_kem_768,
    traits::{Decaps, Encaps, KeyGen, SerDes},
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::foundation::{CanonicalItem, CanonicalTuple, kmac256};

pub const ENCRYPTION_KEY_BYTE_LENGTH: usize = ml_kem_768::EK_LEN;
pub const DECRYPTION_KEY_BYTE_LENGTH: usize = ml_kem_768::DK_LEN;
pub const KEM_CIPHERTEXT_BYTE_LENGTH: usize = ml_kem_768::CT_LEN;
pub const KEY_GENERATION_RANDOMNESS_BYTE_LENGTH: usize = 64;
pub const ENCRYPTION_RANDOMNESS_BYTE_LENGTH: usize = 32;
pub const KDF_CONTEXT_BYTE_LENGTH: usize = 356;

const AEAD_KEY_BYTE_LENGTH: usize = 32;
const AEAD_NONCE_BYTE_LENGTH: usize = 12;
const MAILBOX_KDF_SCHEMA_IDENTIFIER: u16 = 0x0210;
const MAILBOX_KDF_SCHEMA_VERSION: u16 = 1;
const MAILBOX_AEAD_KEY_CUSTOMIZATION: &[u8] = b"sealed-lattice/mailbox/aead-key/v1";
const MAILBOX_CHUNK_NONCE_CUSTOMIZATION: &[u8] = b"sealed-lattice/mailbox/chunk-nonce/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairEncryptionError {
    InvalidCiphertext,
    InvalidCiphertextLength,
    InvalidDecryptionKey,
    InvalidDecryptionKeyLength,
    InvalidEncryptionKey,
    InvalidEncryptionKeyLength,
    InvalidEncryptionRandomnessLength,
    InvalidKdfContextLength,
    InvalidKdfEncoding,
    InvalidKeyGenerationRandomnessLength,
    WrongKeyPair,
}

impl fmt::Display for PairEncryptionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCiphertext => "ML-KEM-768 mailbox ciphertext is invalid",
            Self::InvalidCiphertextLength => "ML-KEM-768 ciphertext has the wrong length",
            Self::InvalidDecryptionKey => "ML-KEM-768 decapsulation key is invalid",
            Self::InvalidDecryptionKeyLength => "ML-KEM-768 decapsulation key has the wrong length",
            Self::InvalidEncryptionKey => "ML-KEM-768 encapsulation key is invalid",
            Self::InvalidEncryptionKeyLength => "ML-KEM-768 encapsulation key has the wrong length",
            Self::InvalidEncryptionRandomnessLength => {
                "ML-KEM-768 encapsulation randomness has the wrong length"
            }
            Self::InvalidKdfContextLength => "mailbox KDF context has the wrong length",
            Self::InvalidKdfEncoding => "mailbox KDF input is not canonically encodable",
            Self::InvalidKeyGenerationRandomnessLength => {
                "ML-KEM-768 key-generation randomness has the wrong length"
            }
            Self::WrongKeyPair => "ML-KEM-768 encapsulation and decapsulation keys do not match",
        })
    }
}

impl std::error::Error for PairEncryptionError {}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairEncryptionKeyPair {
    #[zeroize(skip)]
    pub encryption_key: [u8; ENCRYPTION_KEY_BYTE_LENGTH],
    pub decryption_key: [u8; DECRYPTION_KEY_BYTE_LENGTH],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairEncryptionMaterial {
    pub(super) aead_key: [u8; AEAD_KEY_BYTE_LENGTH],
    pub(super) nonce: [u8; AEAD_NONCE_BYTE_LENGTH],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PairEncryptionEncapsulation {
    #[zeroize(skip)]
    pub ciphertext: [u8; KEM_CIPHERTEXT_BYTE_LENGTH],
    pub(super) material: PairEncryptionMaterial,
}

pub fn generate_key_pair(randomness: &[u8]) -> Result<PairEncryptionKeyPair, PairEncryptionError> {
    let randomness: &[u8; KEY_GENERATION_RANDOMNESS_BYTE_LENGTH] = randomness
        .try_into()
        .map_err(|_| PairEncryptionError::InvalidKeyGenerationRandomnessLength)?;
    let (encapsulation_key, decapsulation_key) = ml_kem_768::KG::keygen_from_seed(
        randomness[..32]
            .try_into()
            .map_err(|_| PairEncryptionError::InvalidKeyGenerationRandomnessLength)?,
        randomness[32..]
            .try_into()
            .map_err(|_| PairEncryptionError::InvalidKeyGenerationRandomnessLength)?,
    );
    Ok(PairEncryptionKeyPair {
        encryption_key: encapsulation_key.into_bytes(),
        decryption_key: decapsulation_key.into_bytes(),
    })
}

pub fn validate_encryption_key(encryption_key: &[u8]) -> Result<(), PairEncryptionError> {
    let bytes: [u8; ENCRYPTION_KEY_BYTE_LENGTH] = encryption_key
        .try_into()
        .map_err(|_| PairEncryptionError::InvalidEncryptionKeyLength)?;
    let parsed = ml_kem_768::EncapsKey::try_from_bytes(bytes)
        .map_err(|_| PairEncryptionError::InvalidEncryptionKey)?;
    if parsed.into_bytes() != bytes {
        return Err(PairEncryptionError::InvalidEncryptionKey);
    }
    Ok(())
}

pub fn validate_key_pair(
    encryption_key: &[u8],
    decryption_key: &[u8],
) -> Result<(), PairEncryptionError> {
    let encryption_key_bytes: [u8; ENCRYPTION_KEY_BYTE_LENGTH] = encryption_key
        .try_into()
        .map_err(|_| PairEncryptionError::InvalidEncryptionKeyLength)?;
    validate_encryption_key(&encryption_key_bytes)?;
    let decryption_key_bytes: Zeroizing<[u8; DECRYPTION_KEY_BYTE_LENGTH]> = Zeroizing::new(
        decryption_key
            .try_into()
            .map_err(|_| PairEncryptionError::InvalidDecryptionKeyLength)?,
    );
    let embedded_key_start = DECRYPTION_KEY_BYTE_LENGTH - ENCRYPTION_KEY_BYTE_LENGTH - 64;
    if decryption_key_bytes[embedded_key_start..embedded_key_start + ENCRYPTION_KEY_BYTE_LENGTH]
        != encryption_key_bytes
    {
        return Err(PairEncryptionError::WrongKeyPair);
    }
    let parsed = ml_kem_768::DecapsKey::try_from_bytes(*decryption_key_bytes)
        .map_err(|_| PairEncryptionError::InvalidDecryptionKey)?;
    if parsed.into_bytes() != *decryption_key_bytes {
        return Err(PairEncryptionError::InvalidDecryptionKey);
    }
    Ok(())
}

pub fn encapsulate(
    encryption_key: &[u8],
    randomness: &[u8],
    kdf_context: &[u8],
) -> Result<PairEncryptionEncapsulation, PairEncryptionError> {
    let encryption_key_bytes: [u8; ENCRYPTION_KEY_BYTE_LENGTH] = encryption_key
        .try_into()
        .map_err(|_| PairEncryptionError::InvalidEncryptionKeyLength)?;
    let encapsulation_key = ml_kem_768::EncapsKey::try_from_bytes(encryption_key_bytes)
        .map_err(|_| PairEncryptionError::InvalidEncryptionKey)?;
    let randomness: &[u8; ENCRYPTION_RANDOMNESS_BYTE_LENGTH] = randomness
        .try_into()
        .map_err(|_| PairEncryptionError::InvalidEncryptionRandomnessLength)?;
    require_kdf_context(kdf_context)?;
    let (shared_secret, ciphertext) = encapsulation_key.encaps_from_seed(randomness);
    let ciphertext = ciphertext.into_bytes();
    let shared_secret = Zeroizing::new(shared_secret.into_bytes());
    let material = derive_material(
        &shared_secret,
        &encryption_key_bytes,
        &ciphertext,
        kdf_context,
    )?;
    Ok(PairEncryptionEncapsulation {
        ciphertext,
        material,
    })
}

pub fn decapsulate(
    encryption_key: &[u8],
    decryption_key: &[u8],
    ciphertext: &[u8],
    kdf_context: &[u8],
) -> Result<PairEncryptionMaterial, PairEncryptionError> {
    let encryption_key_bytes: [u8; ENCRYPTION_KEY_BYTE_LENGTH] = encryption_key
        .try_into()
        .map_err(|_| PairEncryptionError::InvalidEncryptionKeyLength)?;
    validate_key_pair(&encryption_key_bytes, decryption_key)?;
    require_kdf_context(kdf_context)?;
    let decryption_key_bytes: Zeroizing<[u8; DECRYPTION_KEY_BYTE_LENGTH]> = Zeroizing::new(
        decryption_key
            .try_into()
            .map_err(|_| PairEncryptionError::InvalidDecryptionKeyLength)?,
    );
    let ciphertext_bytes: [u8; KEM_CIPHERTEXT_BYTE_LENGTH] = ciphertext
        .try_into()
        .map_err(|_| PairEncryptionError::InvalidCiphertextLength)?;

    let decapsulation_key = ml_kem_768::DecapsKey::try_from_bytes(*decryption_key_bytes)
        .map_err(|_| PairEncryptionError::InvalidDecryptionKey)?;
    let ciphertext = ml_kem_768::CipherText::try_from_bytes(ciphertext_bytes)
        .map_err(|_| PairEncryptionError::InvalidCiphertext)?;
    let shared_secret = decapsulation_key
        .try_decaps(&ciphertext)
        .map_err(|_| PairEncryptionError::InvalidCiphertext)?;
    let shared_secret = Zeroizing::new(shared_secret.into_bytes());
    derive_material(
        &shared_secret,
        &encryption_key_bytes,
        &ciphertext_bytes,
        kdf_context,
    )
}

fn require_kdf_context(kdf_context: &[u8]) -> Result<(), PairEncryptionError> {
    if kdf_context.len() != KDF_CONTEXT_BYTE_LENGTH {
        return Err(PairEncryptionError::InvalidKdfContextLength);
    }
    Ok(())
}

fn derive_material(
    shared_secret: &[u8; 32],
    encryption_key: &[u8; ENCRYPTION_KEY_BYTE_LENGTH],
    ciphertext: &[u8; KEM_CIPHERTEXT_BYTE_LENGTH],
    kdf_context: &[u8],
) -> Result<PairEncryptionMaterial, PairEncryptionError> {
    let input = Zeroizing::new(mailbox_kdf_input(encryption_key, ciphertext, kdf_context)?);
    Ok(PairEncryptionMaterial {
        aead_key: kmac256::<AEAD_KEY_BYTE_LENGTH>(
            shared_secret,
            &input,
            MAILBOX_AEAD_KEY_CUSTOMIZATION,
        ),
        nonce: kmac256::<AEAD_NONCE_BYTE_LENGTH>(
            shared_secret,
            &input,
            MAILBOX_CHUNK_NONCE_CUSTOMIZATION,
        ),
    })
}

fn mailbox_kdf_input(
    encryption_key: &[u8; ENCRYPTION_KEY_BYTE_LENGTH],
    ciphertext: &[u8; KEM_CIPHERTEXT_BYTE_LENGTH],
    kdf_context: &[u8],
) -> Result<Vec<u8>, PairEncryptionError> {
    require_kdf_context(kdf_context)?;
    CanonicalTuple::new(
        MAILBOX_KDF_SCHEMA_IDENTIFIER,
        MAILBOX_KDF_SCHEMA_VERSION,
        vec![
            CanonicalItem::fixed_bytes(encryption_key)
                .map_err(|_| PairEncryptionError::InvalidKdfEncoding)?,
            CanonicalItem::fixed_bytes(ciphertext)
                .map_err(|_| PairEncryptionError::InvalidKdfEncoding)?,
            CanonicalItem::fixed_bytes(kdf_context)
                .map_err(|_| PairEncryptionError::InvalidKdfEncoding)?,
        ],
    )
    .encode()
    .map_err(|_| PairEncryptionError::InvalidKdfEncoding)
}

#[cfg(test)]
mod tests {
    use sha3::{Digest, Sha3_512};

    use super::*;

    fn decode_hex<const BYTE_LENGTH: usize>(hex: &str) -> [u8; BYTE_LENGTH] {
        assert_eq!(hex.len(), 2 * BYTE_LENGTH);
        core::array::from_fn(|index| {
            u8::from_str_radix(&hex[2 * index..2 * index + 2], 16).expect("valid hex")
        })
    }

    #[test]
    fn matches_nist_acvp_ml_kem_768_keygen_case_26() {
        let d =
            decode_hex::<32>("e34a701c4c87582f42264ee422d3c684d97611f2523efe0c998af05056d693dc");
        let z =
            decode_hex::<32>("a85768f3486bd32a01bf9a8f21ea938e648eae4e5448c34c3eb88820b159eedd");
        let expected_encryption_key_digest = decode_hex::<64>(
            "0f3fcedd1e2aff754963212e06ec0d4a4c3876a31a97bed8d862e793f6eed293\
             49d7d38c687bfdccebb4dc882ae73c7a53dda2f5149ca435acda91f53a564524",
        );
        let expected_decryption_key_digest = decode_hex::<64>(
            "6c2e9802eb268cbdeb2d78e36dba31ffd7b1e1b53e782fd8aa783fd316fa17c3\
             dc31026248c01209613421d2a1f310fd443debf1a25e519d3fe990cd71f15252",
        );
        let mut randomness = [0_u8; KEY_GENERATION_RANDOMNESS_BYTE_LENGTH];
        randomness[..32].copy_from_slice(&d);
        randomness[32..].copy_from_slice(&z);
        let key_pair = generate_key_pair(&randomness).expect("ACVP seeds generate a key pair");
        assert_eq!(
            Sha3_512::digest(key_pair.encryption_key).as_slice(),
            expected_encryption_key_digest,
        );
        assert_eq!(
            Sha3_512::digest(key_pair.decryption_key).as_slice(),
            expected_decryption_key_digest,
        );
    }

    #[test]
    fn mailbox_kdf_has_independent_key_and_nonce_outputs() {
        let shared_secret = core::array::from_fn::<_, 32, _>(|index| index as u8);
        let encryption_key = core::array::from_fn::<_, ENCRYPTION_KEY_BYTE_LENGTH, _>(|index| {
            (index * 17 + 3) as u8
        });
        let ciphertext = core::array::from_fn::<_, KEM_CIPHERTEXT_BYTE_LENGTH, _>(|index| {
            (index * 29 + 7) as u8
        });
        let context =
            core::array::from_fn::<_, KDF_CONTEXT_BYTE_LENGTH, _>(|index| (index * 43 + 11) as u8);
        let input = mailbox_kdf_input(&encryption_key, &ciphertext, &context)
            .expect("mailbox KDF input encodes");
        assert_eq!(input.len(), 2_654);
        assert_eq!(
            Sha3_512::digest(&input).as_slice(),
            decode_hex::<64>(
                "2bd063be2e0ef8a7a31de35f40a2b34e51787b033d6a62534e545745aa927d1b\
                 97c76fa12390bbeffbab3beba2e29909cc36f3031aa05a5ed0888b281315e7c9",
            ),
        );
        let material = derive_material(&shared_secret, &encryption_key, &ciphertext, &context)
            .expect("mailbox material derives");
        assert_eq!(
            material.aead_key,
            decode_hex::<AEAD_KEY_BYTE_LENGTH>(
                "235c9ede0083e7031079c3b9b905503b774d502b269e14c5843cd68ffa91f5bb",
            ),
        );
        assert_eq!(
            material.nonce,
            decode_hex::<AEAD_NONCE_BYTE_LENGTH>("c6d75bf17c8a124fc2b692dc"),
        );
    }

    fn key_pair(seed: u8) -> PairEncryptionKeyPair {
        let mut randomness = [seed; KEY_GENERATION_RANDOMNESS_BYTE_LENGTH];
        randomness[32] ^= 0x5a;
        generate_key_pair(&randomness).expect("ML-KEM key generation succeeds")
    }

    fn replace_public_key_coefficient(
        encryption_key: &mut [u8; ENCRYPTION_KEY_BYTE_LENGTH],
        coefficient_position: usize,
        coefficient: u16,
    ) {
        assert!(coefficient_position < 3 * 256);
        assert!(coefficient < 1 << 12);
        let byte_position = 3 * (coefficient_position / 2);
        if coefficient_position.is_multiple_of(2) {
            encryption_key[byte_position] = coefficient as u8;
            encryption_key[byte_position + 1] =
                (encryption_key[byte_position + 1] & 0xf0) | ((coefficient >> 8) as u8 & 0x0f);
        } else {
            encryption_key[byte_position + 1] =
                (encryption_key[byte_position + 1] & 0x0f) | ((coefficient as u8 & 0x0f) << 4);
            encryption_key[byte_position + 2] = (coefficient >> 4) as u8;
        }
    }

    #[test]
    fn public_key_coefficients_enforce_the_exact_ml_kem_modulus_boundary() {
        const ML_KEM_MODULUS: u16 = 3_329;
        let pair = key_pair(0x30);
        for coefficient_position in [0, 1, 255, 256, 511, 767] {
            let mut largest_canonical = pair.encryption_key;
            replace_public_key_coefficient(
                &mut largest_canonical,
                coefficient_position,
                ML_KEM_MODULUS - 1,
            );
            assert_eq!(validate_encryption_key(&largest_canonical), Ok(()));

            let mut first_noncanonical = pair.encryption_key;
            replace_public_key_coefficient(
                &mut first_noncanonical,
                coefficient_position,
                ML_KEM_MODULUS,
            );
            assert_eq!(
                validate_encryption_key(&first_noncanonical),
                Err(PairEncryptionError::InvalidEncryptionKey),
            );
        }
    }

    #[test]
    fn exact_ml_kem_encapsulation_round_trip_and_context_binding() {
        let pair = key_pair(0x31);
        assert_eq!(pair.encryption_key.len(), 1_184);
        assert_eq!(pair.decryption_key.len(), 2_400);
        let randomness = [0x83; ENCRYPTION_RANDOMNESS_BYTE_LENGTH];
        let context = [0x47; KDF_CONTEXT_BYTE_LENGTH];
        let encapsulated = encapsulate(&pair.encryption_key, &randomness, &context)
            .expect("ML-KEM encapsulation succeeds");
        let material = decapsulate(
            &pair.encryption_key,
            &pair.decryption_key,
            &encapsulated.ciphertext,
            &context,
        )
        .expect("mailbox decapsulation succeeds");
        assert_eq!(material.aead_key, encapsulated.material.aead_key);
        assert_eq!(material.nonce, encapsulated.material.nonce);

        let mut other_context = context;
        other_context[0] ^= 1;
        let other_material = decapsulate(
            &pair.encryption_key,
            &pair.decryption_key,
            &encapsulated.ciphertext,
            &other_context,
        )
        .expect("the KEM remains structurally valid under another context");
        assert_ne!(other_material.aead_key, material.aead_key);
        assert_ne!(other_material.nonce, material.nonce);
    }

    #[test]
    fn malformed_and_mismatched_keys_fail_closed() {
        let pair = key_pair(0x32);
        let other = key_pair(0x33);
        let context = [0x57; KDF_CONTEXT_BYTE_LENGTH];
        let encapsulated = encapsulate(
            &pair.encryption_key,
            &[0x72; ENCRYPTION_RANDOMNESS_BYTE_LENGTH],
            &context,
        )
        .expect("mailbox encapsulation succeeds");
        assert!(matches!(
            decapsulate(
                &pair.encryption_key,
                &other.decryption_key,
                &encapsulated.ciphertext,
                &context,
            ),
            Err(PairEncryptionError::WrongKeyPair)
        ));
        assert_eq!(
            validate_encryption_key(&pair.encryption_key[..ENCRYPTION_KEY_BYTE_LENGTH - 1]),
            Err(PairEncryptionError::InvalidEncryptionKeyLength),
        );
        assert!(matches!(
            encapsulate(
                &pair.encryption_key,
                &[0; ENCRYPTION_RANDOMNESS_BYTE_LENGTH - 1],
                &context,
            ),
            Err(PairEncryptionError::InvalidEncryptionRandomnessLength)
        ));
        assert!(matches!(
            decapsulate(
                &pair.encryption_key,
                &pair.decryption_key,
                &encapsulated.ciphertext[..KEM_CIPHERTEXT_BYTE_LENGTH - 1],
                &context,
            ),
            Err(PairEncryptionError::InvalidCiphertextLength)
        ));
        assert_eq!(
            encapsulate(
                &pair.encryption_key,
                &[0x72; ENCRYPTION_RANDOMNESS_BYTE_LENGTH],
                &context[..KDF_CONTEXT_BYTE_LENGTH - 1],
            )
            .err(),
            Some(PairEncryptionError::InvalidKdfContextLength),
        );
    }
}
