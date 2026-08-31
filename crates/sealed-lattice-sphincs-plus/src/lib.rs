//! Exact SPHINCS+-SHA2-192f-robust round 3.1 signature profile.
//!
//! The algorithm body is a stable-Rust, fixed-profile adaptation of
//! `pqc_sphincsplus` 0.2.0 (crate checksum
//! `12672c0e23811d068ab9eecf1e5c9a8a5c6d981ec1a0e39510eacd4d93438a62`,
//! source commit `53e76a674fdcf6664041ca7275a070d408b07526`). The implementation is
//! byte-checked against the official SPHINCS+ reference implementation at
//! commit `7ec789ace6874d875f4bb84cb61b81155398167e`.

#![no_std]

mod address;
mod context;
mod fors;
mod hash;
mod merkle;
mod offsets;
mod params;
mod sha2;
mod sign;
mod thash;
mod utils;
mod utilsx1;
mod wots;
mod wotsx1;

use zeroize::Zeroizing;

pub const PUBLIC_KEY_BYTE_LENGTH: usize = params::CRYPTO_PUBLICKEYBYTES;
pub const SECRET_KEY_BYTE_LENGTH: usize = params::CRYPTO_SECRETKEYBYTES;
pub const SIGNATURE_BYTE_LENGTH: usize = params::CRYPTO_BYTES;
pub const KEY_GENERATION_SEED_BYTE_LENGTH: usize = params::CRYPTO_SEEDBYTES;
pub const SIGNATURE_RANDOMIZER_BYTE_LENGTH: usize = params::SPX_N;

pub type PublicKey = [u8; PUBLIC_KEY_BYTE_LENGTH];
pub type SecretKey = [u8; SECRET_KEY_BYTE_LENGTH];
pub type Signature = [u8; SIGNATURE_BYTE_LENGTH];
pub type KeyGenerationSeed = [u8; KEY_GENERATION_SEED_BYTE_LENGTH];
pub type SignatureRandomizer = [u8; SIGNATURE_RANDOMIZER_BYTE_LENGTH];

pub fn keypair_from_seed(seed: &KeyGenerationSeed) -> (PublicKey, SecretKey) {
    let seed = Zeroizing::new(*seed);
    let mut public_key = [0_u8; PUBLIC_KEY_BYTE_LENGTH];
    let mut secret_key = [0_u8; SECRET_KEY_BYTE_LENGTH];
    sign::crypto_sign_seed_keypair(&mut public_key, &mut secret_key, &seed[..]);
    (public_key, secret_key)
}

pub fn public_key_from_secret_key(secret_key: &SecretKey) -> PublicKey {
    let mut public_key = [0_u8; PUBLIC_KEY_BYTE_LENGTH];
    public_key.copy_from_slice(&secret_key[2 * params::SPX_N..4 * params::SPX_N]);
    public_key
}

pub fn sign(message: &[u8], secret_key: &SecretKey, randomizer: &SignatureRandomizer) -> Signature {
    let secret_key = Zeroizing::new(*secret_key);
    let randomizer = Zeroizing::new(*randomizer);
    let mut signature = [0_u8; SIGNATURE_BYTE_LENGTH];
    sign::crypto_sign_signature(&mut signature, message, &secret_key[..], &randomizer[..]);
    signature
}

pub fn verify(signature: &Signature, message: &[u8], public_key: &PublicKey) -> bool {
    sign::crypto_sign_verify(signature, message, public_key)
}

#[cfg(test)]
mod tests {
    use sha256::{Digest, Sha256};

    use super::*;

    fn deterministic_bytes<const LENGTH: usize>(seed: u32, ordinal: u32) -> [u8; LENGTH] {
        let mut bytes = [0_u8; LENGTH];
        let mut state = 0x9e37_79b9_u32 ^ seed ^ ordinal.rotate_left(13);
        for byte in &mut bytes {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            *byte = state as u8;
        }
        bytes
    }

    #[test]
    fn exact_profile_matches_the_official_reference_vector() {
        const PUBLIC_KEY_DIGEST: [u8; 32] = [
            0x9b, 0x69, 0xcd, 0xf7, 0x50, 0xdc, 0x84, 0x35, 0x29, 0xab, 0xf1, 0xb7, 0x5f, 0x9c,
            0xa7, 0x95, 0xef, 0x7f, 0xca, 0x4b, 0x48, 0x47, 0xa7, 0x36, 0xa0, 0xaf, 0x89, 0xe2,
            0x0e, 0x33, 0x12, 0x68,
        ];
        const SIGNATURE_DIGEST: [u8; 32] = [
            0xe4, 0x2d, 0x23, 0xe9, 0x1a, 0xe0, 0x1b, 0x97, 0x78, 0xde, 0x61, 0xbe, 0xc9, 0x99,
            0xf9, 0xd4, 0x1b, 0x05, 0x60, 0xc1, 0xfa, 0xd4, 0x6a, 0xc4, 0x69, 0x54, 0x18, 0xba,
            0xde, 0x07, 0x7b, 0x26,
        ];

        assert_eq!(PUBLIC_KEY_BYTE_LENGTH, 48);
        assert_eq!(SECRET_KEY_BYTE_LENGTH, 96);
        assert_eq!(SIGNATURE_BYTE_LENGTH, 35_664);
        assert_eq!(KEY_GENERATION_SEED_BYTE_LENGTH, 72);
        assert_eq!(SIGNATURE_RANDOMIZER_BYTE_LENGTH, 24);

        let seed_value = 0x1357_9bdf_u32;
        let key_seed = deterministic_bytes::<KEY_GENERATION_SEED_BYTE_LENGTH>(seed_value, 0);
        let randomizer = deterministic_bytes::<SIGNATURE_RANDOMIZER_BYTE_LENGTH>(seed_value, 1);
        let mut message = deterministic_bytes::<96>(seed_value, 0);
        message[..4].copy_from_slice(&seed_value.to_le_bytes());
        message[4..8].copy_from_slice(&0_u32.to_le_bytes());

        let (public_key, secret_key) = keypair_from_seed(&key_seed);
        assert_eq!(public_key_from_secret_key(&secret_key), public_key);
        let mut signature = sign(&message, &secret_key, &randomizer);

        assert_eq!(Sha256::digest(public_key).as_slice(), PUBLIC_KEY_DIGEST);
        assert_eq!(Sha256::digest(signature).as_slice(), SIGNATURE_DIGEST);
        assert!(verify(&signature, &message, &public_key));

        signature[SIGNATURE_BYTE_LENGTH - 1] ^= 1;
        assert!(!verify(&signature, &message, &public_key));
    }
}
