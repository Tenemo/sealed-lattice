//! The fixed-length protocol digest: the first 64 SHAKE256 output bytes
//! after a fixed 64-byte domain prefix and the caller's framed input.
//! The prefix separates these calls from the compiler's wide challenges.
//! FIPS 202 fixes the rate and suffix; RustCrypto's pinned backends provide
//! absorption and Keccak-f. The authenticated checkpoint keeps the lanes
//! and cursor, never an algorithm selector or a transferable verdict.

use digest::{
    FixedOutput, HashMarker, Output, OutputSizeUser, Update,
    common::hazmat::{DeserializeStateError, SerializableState, SerializedState},
    consts::{U64, U201},
};
use keccak::{Keccak, State1600};
use sponge_cursor::SpongeCursor;
use zeroize::Zeroize;

const RATE: usize = 136;
const PREFIX_BYTES: usize = 64;
const DOMAIN: &[u8] = b"sealed-lattice/fixed-hash/v1";

#[derive(Clone)]
pub struct ProtocolHash {
    state: State1600,
    cursor: SpongeCursor<RATE>,
    keccak: Keccak,
}

impl ProtocolHash {
    /// The cursor after the fixed domain prefix and this many message bytes.
    /// Checkpoint restoration uses the same rate as the absorbing backend.
    pub fn absorption_cursor_after(message_bytes: usize) -> usize {
        (PREFIX_BYTES + message_bytes % RATE) % RATE
    }
}

impl Default for ProtocolHash {
    fn default() -> Self {
        let mut hash = Self {
            state: Default::default(),
            cursor: Default::default(),
            keccak: Keccak::new(),
        };
        let mut prefix = [0; PREFIX_BYTES];
        prefix[..DOMAIN.len()].copy_from_slice(DOMAIN);
        Update::update(&mut hash, &prefix);
        hash
    }
}

impl HashMarker for ProtocolHash {}
impl OutputSizeUser for ProtocolHash {
    type OutputSize = U64;
}
impl Update for ProtocolHash {
    fn update(&mut self, bytes: &[u8]) {
        self.keccak.with_f1600(|permutation| {
            self.cursor
                .absorb_u64_le(&mut self.state, permutation, bytes);
        });
    }
}
impl FixedOutput for ProtocolHash {
    fn finalize_into(mut self, output: &mut Output<Self>) {
        // SHAKE's delimited suffix is 0x1f; pad10*1 ends at the rate's
        // final bit. Only one output block is needed for this digest.
        let position = self.cursor.pos();
        self.state[position / 8] ^= 0x1f_u64 << (8 * (position % 8));
        self.state[RATE / 8 - 1] ^= 1_u64 << 63;
        self.keccak
            .with_f1600(|permutation| permutation(&mut self.state));
        for (word, bytes) in self.state.iter().zip(output.chunks_exact_mut(8)) {
            bytes.copy_from_slice(&word.to_le_bytes());
        }
    }
}

impl SerializableState for ProtocolHash {
    type SerializedStateSize = U201;
    fn serialize(&self) -> SerializedState<Self> {
        let mut bytes = [0; 201];
        for (word, destination) in self.state.iter().zip(bytes[..200].chunks_exact_mut(8)) {
            destination.copy_from_slice(&word.to_le_bytes());
        }
        bytes[200] = self.cursor.raw_pos();
        bytes.into()
    }
    fn deserialize(bytes: &SerializedState<Self>) -> Result<Self, DeserializeStateError> {
        let cursor = SpongeCursor::new(bytes[200]).ok_or(DeserializeStateError)?;
        Ok(Self {
            state: core::array::from_fn(|index| {
                u64::from_le_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap())
            }),
            cursor,
            keccak: Keccak::new(),
        })
    }
}
impl Drop for ProtocolHash {
    fn drop(&mut self) {
        self.state.zeroize();
        self.cursor.zeroize();
    }
}
impl zeroize::ZeroizeOnDrop for ProtocolHash {}

#[cfg(test)]
mod tests {
    use super::*;
    use digest::Digest;

    fn message(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index * 131 % 251) as u8).collect()
    }
    fn hexadecimal(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // Independent Python hashlib/OpenSSL SHAKE256 vectors over the literal
    // domain padded with zeroes to 64 bytes, followed by each message.
    #[test]
    fn matches_independent_shake256_vectors() {
        for (input, expected) in [
            (
                vec![],
                "29adf64c397cdd7c2a12c1394f67914da8987f45a7101fd4cd7b39eb289ed7df625620af7fd1951404e3042f65b8fb91a69ff9c1ca7ef0975b76f136a9ca6e96",
            ),
            (
                b"abc".to_vec(),
                "a8df42eb0a2bad96d4d5fde4a7896c5f31287bf651801f3335038cd92aaf3b7f35c81fc12490ef51cd4efb534428f6abc938956e876ea85dd5c669bf484d86fc",
            ),
            (
                (0..137).collect(),
                "22144d386270491cf53fe8e489fc2d5be1e79520869e05c840eb8a05c509364ee3c2d369e2a91ceb6c25b1ca0e4b22ed96fe7b73adbbbbc42e7c6fffc5985ca4",
            ),
            (
                message(4097),
                "14a76849aa7c6fd964ce1df16a2683f1c00a1998b5def2934db5b24d017e85d461c729927b4038cad29c986d0b5ae51b5a3a14aaa9d63a81fa1891ed099d7972",
            ),
        ] {
            assert_eq!(hexadecimal(&ProtocolHash::digest(&input)), expected);
        }
    }

    #[test]
    fn checkpoints_continue_across_absorption_boundaries() {
        let input = message(4097);
        let expected = "14a76849aa7c6fd964ce1df16a2683f1c00a1998b5def2934db5b24d017e85d461c729927b4038cad29c986d0b5ae51b5a3a14aaa9d63a81fa1891ed099d7972";
        for split in [0, 1, 71, 72, 73, 135, 136, 137, 207, 208, 209, 4096, 4097] {
            let mut first = ProtocolHash::new();
            Digest::update(&mut first, &input[..split]);
            let mut restored = ProtocolHash::deserialize(&first.serialize()).unwrap();
            for chunk in input[split..].chunks(17) {
                Digest::update(&mut restored, chunk);
            }
            assert_eq!(hexadecimal(&restored.finalize()), expected, "split {split}");
        }
        let mut state = ProtocolHash::new().serialize();
        for cursor in [136, 137, 255] {
            state[200] = cursor;
            assert!(ProtocolHash::deserialize(&state).is_err());
        }
    }
}
