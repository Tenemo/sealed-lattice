//! The local custody of one secret record: AES-256-GCM under a fresh key that
//! seals nothing else, so the record's fixed zero nonce never repeats under
//! its key. The caller retains the key, and the associated data binds the
//! record to its context.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use zeroize::Zeroizing;

/// The bytes of a record's key.
pub const KEY_BYTES: usize = 32;
/// The bytes a sealed record adds to its plaintext.
pub const TAG_BYTES: usize = 16;

/// A record sealed under its own fresh key.
pub struct Sealed {
    pub key: Zeroizing<[u8; KEY_BYTES]>,
    pub bytes: Vec<u8>,
}

/// Seals the plaintext under a fresh key.
pub fn seal(plaintext: &[u8], associated: &[u8]) -> Sealed {
    let mut key = Zeroizing::new([0; KEY_BYTES]);
    crate::random::fresh(key.as_mut());
    // The buffer holds the tag too, so sealing never moves the plaintext.
    let mut bytes = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_BYTES));
    bytes.extend_from_slice(plaintext);
    Aes256Gcm::new((&*key).into())
        .encrypt_in_place(Nonce::from_slice(&[0; 12]), associated, &mut *bytes)
        .expect("A record within the cipher's bound seals.");
    Sealed {
        key,
        bytes: std::mem::take(&mut *bytes),
    }
}

/// Opens a sealed record with its key, or refuses one that does not
/// authenticate under the associated data.
pub fn open(key: &[u8; KEY_BYTES], associated: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(sealed.to_vec());
    Aes256Gcm::new(key.into())
        .decrypt_in_place(Nonce::from_slice(&[0; 12]), associated, &mut *bytes)
        .ok()?;
    Some(bytes)
}

#[cfg(test)]
#[path = "sealing-tests.rs"]
mod tests;
