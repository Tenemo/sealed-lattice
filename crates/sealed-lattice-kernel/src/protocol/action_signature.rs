use core::fmt;

use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const KEY_GENERATION_RANDOMNESS_BYTE_LENGTH: usize = 32;
pub const SIGNING_RANDOMNESS_BYTE_LENGTH: usize = 32;
pub const SECRET_KEY_BYTE_LENGTH: usize = ml_dsa_65::SK_LEN;
pub const VERIFICATION_KEY_BYTE_LENGTH: usize = ml_dsa_65::PK_LEN;
pub const SIGNATURE_BYTE_LENGTH: usize = ml_dsa_65::SIG_LEN;
pub const MESSAGE_BYTE_LENGTH: usize = 64;

const SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/action-signature/v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionSignatureError {
    InvalidKeyGenerationRandomnessLength,
    InvalidMessageLength,
    InvalidSecretKey,
    InvalidSecretKeyLength,
    InvalidSignatureLength,
    InvalidSigningRandomnessLength,
    InvalidVerificationKey,
    InvalidVerificationKeyLength,
    SigningFailed,
}

impl fmt::Display for ActionSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidKeyGenerationRandomnessLength => {
                "ML-DSA-65 key-generation randomness has the wrong length"
            }
            Self::InvalidMessageLength => "action-signature message has the wrong length",
            Self::InvalidSecretKey => "action-signature secret key is not a valid ML-DSA-65 key",
            Self::InvalidSecretKeyLength => "action-signature secret key has the wrong length",
            Self::InvalidSignatureLength => "action signature has the wrong length",
            Self::InvalidSigningRandomnessLength => {
                "ML-DSA-65 signing randomness has the wrong length"
            }
            Self::InvalidVerificationKey => {
                "action-signature verification key is not a valid ML-DSA-65 key"
            }
            Self::InvalidVerificationKeyLength => {
                "action-signature verification key has the wrong length"
            }
            Self::SigningFailed => "ML-DSA-65 signing failed",
        })
    }
}

impl std::error::Error for ActionSignatureError {}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ActionSignatureKeyPair {
    pub secret_key: [u8; SECRET_KEY_BYTE_LENGTH],
    #[zeroize(skip)]
    pub verification_key: [u8; VERIFICATION_KEY_BYTE_LENGTH],
}

pub fn generate_key_pair(
    randomness: &[u8],
) -> Result<ActionSignatureKeyPair, ActionSignatureError> {
    let seed: &[u8; KEY_GENERATION_RANDOMNESS_BYTE_LENGTH] = randomness
        .try_into()
        .map_err(|_| ActionSignatureError::InvalidKeyGenerationRandomnessLength)?;
    let (verification_key, secret_key) = ml_dsa_65::KG::keygen_from_seed(seed);
    Ok(ActionSignatureKeyPair {
        secret_key: secret_key.into_bytes(),
        verification_key: verification_key.into_bytes(),
    })
}

pub fn derive_verification_key(
    secret_key: &[u8],
) -> Result<[u8; VERIFICATION_KEY_BYTE_LENGTH], ActionSignatureError> {
    let mut bytes: [u8; SECRET_KEY_BYTE_LENGTH] = secret_key
        .try_into()
        .map_err(|_| ActionSignatureError::InvalidSecretKeyLength)?;
    let parsed = ml_dsa_65::PrivateKey::try_from_bytes(bytes);
    bytes.zeroize();
    let parsed = parsed.map_err(|_| ActionSignatureError::InvalidSecretKey)?;
    Ok(parsed.get_public_key().into_bytes())
}

pub fn validate_verification_key(verification_key: &[u8]) -> Result<(), ActionSignatureError> {
    let bytes: [u8; VERIFICATION_KEY_BYTE_LENGTH] = verification_key
        .try_into()
        .map_err(|_| ActionSignatureError::InvalidVerificationKeyLength)?;
    let parsed = ml_dsa_65::PublicKey::try_from_bytes(bytes)
        .map_err(|_| ActionSignatureError::InvalidVerificationKey)?;
    if parsed.into_bytes() != bytes {
        return Err(ActionSignatureError::InvalidVerificationKey);
    }
    Ok(())
}

pub fn sign(
    secret_key: &[u8],
    signing_randomness: &[u8],
    message: &[u8],
) -> Result<[u8; SIGNATURE_BYTE_LENGTH], ActionSignatureError> {
    if message.len() != MESSAGE_BYTE_LENGTH {
        return Err(ActionSignatureError::InvalidMessageLength);
    }
    let mut secret_key_bytes: [u8; SECRET_KEY_BYTE_LENGTH] = secret_key
        .try_into()
        .map_err(|_| ActionSignatureError::InvalidSecretKeyLength)?;
    let signing_seed: &[u8; SIGNING_RANDOMNESS_BYTE_LENGTH] = signing_randomness
        .try_into()
        .map_err(|_| ActionSignatureError::InvalidSigningRandomnessLength)?;
    let parsed = ml_dsa_65::PrivateKey::try_from_bytes(secret_key_bytes);
    secret_key_bytes.zeroize();
    let parsed = parsed.map_err(|_| ActionSignatureError::InvalidSecretKey)?;
    parsed
        .try_sign_with_seed(signing_seed, message, SIGNATURE_CONTEXT)
        .map_err(|_| ActionSignatureError::SigningFailed)
}

pub fn verify(
    signature: &[u8],
    verification_key: &[u8],
    message: &[u8],
) -> Result<bool, ActionSignatureError> {
    if message.len() != MESSAGE_BYTE_LENGTH {
        return Err(ActionSignatureError::InvalidMessageLength);
    }
    let signature: &[u8; SIGNATURE_BYTE_LENGTH] = signature
        .try_into()
        .map_err(|_| ActionSignatureError::InvalidSignatureLength)?;
    let verification_key_bytes: [u8; VERIFICATION_KEY_BYTE_LENGTH] = verification_key
        .try_into()
        .map_err(|_| ActionSignatureError::InvalidVerificationKeyLength)?;
    let verification_key = ml_dsa_65::PublicKey::try_from_bytes(verification_key_bytes)
        .map_err(|_| ActionSignatureError::InvalidVerificationKey)?;
    Ok(verification_key.verify(message, signature, SIGNATURE_CONTEXT))
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
    fn matches_nist_acvp_ml_dsa_65_keygen_case_26() {
        let seed =
            decode_hex::<32>("70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c");
        let expected_verification_key_digest = decode_hex::<64>(
            "3357389623a4b6b103258dcd53eab9316ce115c23c4cbe96d20aa4dc852e275e\
             0f3518c550a9cc007a3ca5232d91a76e37263a043c505c7b879503c5fcc87e26",
        );
        let expected_secret_key_digest = decode_hex::<64>(
            "fd032e6a5923c19c131710f71e9f952215aa3b79eb56083746540223d80d461e\
             33058cd6e6a2d477fb9b8b40517420e924d98f86177c31fc1c9c0d64368586df",
        );
        let key_pair = generate_key_pair(&seed).expect("ACVP seed generates a key pair");
        assert_eq!(
            Sha3_512::digest(key_pair.verification_key).as_slice(),
            expected_verification_key_digest,
        );
        assert_eq!(
            Sha3_512::digest(key_pair.secret_key).as_slice(),
            expected_secret_key_digest,
        );
    }

    #[test]
    fn exact_ml_dsa_65_round_trip_and_mutations() {
        let key_pair = generate_key_pair(&[0x23; KEY_GENERATION_RANDOMNESS_BYTE_LENGTH])
            .expect("ML-DSA key generation succeeds");
        assert_eq!(key_pair.secret_key.len(), 4_032);
        assert_eq!(key_pair.verification_key.len(), 1_952);
        assert_eq!(
            derive_verification_key(&key_pair.secret_key)
                .expect("verification key derives from the serialized secret"),
            key_pair.verification_key,
        );

        let message = [0x5a; MESSAGE_BYTE_LENGTH];
        let mut signature = sign(
            &key_pair.secret_key,
            &[0x91; SIGNING_RANDOMNESS_BYTE_LENGTH],
            &message,
        )
        .expect("ML-DSA signing succeeds");
        assert_eq!(signature.len(), 3_309);
        assert!(
            verify(&signature, &key_pair.verification_key, &message)
                .expect("ML-DSA verification runs")
        );

        signature[1_709] ^= 1;
        assert!(
            !verify(&signature, &key_pair.verification_key, &message)
                .expect("mutated signature remains structurally parseable")
        );
        assert!(
            !verify(
                &sign(
                    &key_pair.secret_key,
                    &[0x91; SIGNING_RANDOMNESS_BYTE_LENGTH],
                    &message,
                )
                .expect("replacement signature"),
                &key_pair.verification_key,
                &[0xa5; MESSAGE_BYTE_LENGTH],
            )
            .expect("different-message verification runs")
        );
    }

    #[test]
    fn exact_lengths_and_key_validation_fail_closed() {
        let key_pair = generate_key_pair(&[0x24; KEY_GENERATION_RANDOMNESS_BYTE_LENGTH])
            .expect("ML-DSA key generation succeeds");
        assert!(matches!(
            generate_key_pair(&[0; KEY_GENERATION_RANDOMNESS_BYTE_LENGTH - 1]),
            Err(ActionSignatureError::InvalidKeyGenerationRandomnessLength),
        ));
        assert_eq!(
            sign(
                &key_pair.secret_key,
                &[0; SIGNING_RANDOMNESS_BYTE_LENGTH - 1],
                &[0; MESSAGE_BYTE_LENGTH],
            ),
            Err(ActionSignatureError::InvalidSigningRandomnessLength),
        );
        assert_eq!(
            sign(
                &key_pair.secret_key[..SECRET_KEY_BYTE_LENGTH - 1],
                &[0; SIGNING_RANDOMNESS_BYTE_LENGTH],
                &[0; MESSAGE_BYTE_LENGTH],
            ),
            Err(ActionSignatureError::InvalidSecretKeyLength),
        );
        assert_eq!(
            validate_verification_key(
                &key_pair.verification_key[..VERIFICATION_KEY_BYTE_LENGTH - 1]
            ),
            Err(ActionSignatureError::InvalidVerificationKeyLength),
        );
    }
}
