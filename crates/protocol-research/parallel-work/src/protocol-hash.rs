//! The fixed-length protocol digest: the first 64 SHAKE256 output bytes
//! after a fixed 64-byte domain prefix and the caller's framed input.
//! The prefix separates these calls from the compiler's wide challenges.
//! FIPS 202 fixes the rate and suffix, and the pinned Keccak-f permutes the
//! lanes after each full rate. The authenticated checkpoint keeps the lanes
//! and cursor, never an algorithm selector or a transferable verdict.

use zeroize::Zeroize;

const RATE: usize = 136;
const PREFIX_BYTES: usize = 64;
const DOMAIN: &[u8] = b"sealed-lattice/fixed-hash/v1";

#[derive(Clone)]
pub struct ProtocolHash {
    lanes: [u64; 25],
    /// The offset in the rate of the next absorbed byte.
    cursor: usize,
}

impl ProtocolHash {
    /// Bytes of a serialized state: the little-endian lanes, then the
    /// cursor.
    pub const STATE_BYTES: usize = 201;

    pub fn new() -> Self {
        let mut hash = Self {
            lanes: [0; 25],
            cursor: 0,
        };
        let mut prefix = [0; PREFIX_BYTES];
        prefix[..DOMAIN.len()].copy_from_slice(DOMAIN);
        hash.absorb(&prefix);
        hash
    }

    /// The digest of one input.
    pub fn digest(bytes: impl AsRef<[u8]>) -> [u8; 64] {
        let mut hash = Self::new();
        hash.absorb(bytes.as_ref());
        hash.finalize()
    }

    /// The cursor after the fixed domain prefix and this many message bytes.
    /// Checkpoint restoration uses the same rate as the absorption.
    pub fn absorption_cursor_after(message_bytes: usize) -> usize {
        (PREFIX_BYTES + message_bytes % RATE) % RATE
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.absorb(bytes.as_ref());
    }

    /// Absorbs bytes into the lanes: one at a time up to a lane boundary,
    /// then whole little-endian lanes.
    fn absorb(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            if self.cursor.is_multiple_of(8) && bytes.len() >= 8 {
                let lanes = ((RATE - self.cursor) / 8).min(bytes.len() / 8);
                let (whole, rest) = bytes.split_at(8 * lanes);
                for (lane, word) in self.lanes[self.cursor / 8..]
                    .iter_mut()
                    .zip(whole.chunks_exact(8))
                {
                    *lane ^= u64::from_le_bytes(word.try_into().unwrap());
                }
                self.cursor += whole.len();
                bytes = rest;
            } else {
                self.lanes[self.cursor / 8] ^= u64::from(bytes[0]) << (8 * (self.cursor % 8));
                self.cursor += 1;
                bytes = &bytes[1..];
            }
            if self.cursor == RATE {
                keccak::f1600(&mut self.lanes);
                self.cursor = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 64] {
        // SHAKE's delimited suffix is 0x1f; pad10*1 ends at the rate's
        // final bit. Only one output block is needed for this digest.
        self.lanes[self.cursor / 8] ^= 0x1f_u64 << (8 * (self.cursor % 8));
        self.lanes[RATE / 8 - 1] ^= 1_u64 << 63;
        keccak::f1600(&mut self.lanes);
        let mut output = [0; 64];
        for (lane, bytes) in self.lanes.iter().zip(output.chunks_exact_mut(8)) {
            bytes.copy_from_slice(&lane.to_le_bytes());
        }
        output
    }

    pub fn serialize(&self) -> [u8; Self::STATE_BYTES] {
        let mut bytes = [0; Self::STATE_BYTES];
        for (lane, destination) in self.lanes.iter().zip(bytes[..200].chunks_exact_mut(8)) {
            destination.copy_from_slice(&lane.to_le_bytes());
        }
        bytes[200] = self.cursor as u8;
        bytes
    }

    /// A serialized state, refused when its cursor is outside the rate.
    pub fn deserialize(bytes: &[u8; Self::STATE_BYTES]) -> Option<Self> {
        let cursor = usize::from(bytes[200]);
        (cursor < RATE).then(|| Self {
            lanes: std::array::from_fn(|index| {
                u64::from_le_bytes(bytes[8 * index..8 * index + 8].try_into().unwrap())
            }),
            cursor,
        })
    }
}

impl Default for ProtocolHash {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProtocolHash {
    fn drop(&mut self) {
        self.lanes.zeroize();
        self.cursor.zeroize();
    }
}
impl zeroize::ZeroizeOnDrop for ProtocolHash {}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(length: usize) -> Vec<u8> {
        (0..length).map(|index| (index * 131 % 251) as u8).collect()
    }
    fn hexadecimal(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // Independent Python hashlib/OpenSSL SHAKE256 vectors over the literal
    // domain padded with zeroes to 64 bytes, followed by each message, which
    // every chunking absorbs alike.
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
            for chunk in [1, 3, 7, 8, 9, 64, 135, 136, 137] {
                let mut hash = ProtocolHash::new();
                for part in input.chunks(chunk) {
                    hash.update(part);
                }
                assert_eq!(hexadecimal(&hash.finalize()), expected, "chunk {chunk}");
            }
        }
    }

    #[test]
    fn checkpoints_continue_across_absorption_boundaries() {
        let input = message(4097);
        let expected = "14a76849aa7c6fd964ce1df16a2683f1c00a1998b5def2934db5b24d017e85d461c729927b4038cad29c986d0b5ae51b5a3a14aaa9d63a81fa1891ed099d7972";
        for split in [0, 1, 71, 72, 73, 135, 136, 137, 207, 208, 209, 4096, 4097] {
            let mut first = ProtocolHash::new();
            first.update(&input[..split]);
            let state = first.serialize();
            assert_eq!(
                usize::from(state[200]),
                ProtocolHash::absorption_cursor_after(split)
            );
            let mut restored = ProtocolHash::deserialize(&state).unwrap();
            for chunk in input[split..].chunks(17) {
                restored.update(chunk);
            }
            assert_eq!(hexadecimal(&restored.finalize()), expected, "split {split}");
        }
        let mut state = ProtocolHash::new().serialize();
        for cursor in [136, 137, 255] {
            state[200] = cursor;
            assert!(ProtocolHash::deserialize(&state).is_none());
        }
    }
}
