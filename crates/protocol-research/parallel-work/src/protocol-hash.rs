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
#[path = "protocol-hash-tests.rs"]
mod tests;
