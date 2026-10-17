use crate::field::{Element, MODULUS};
use parallel_work::ProtocolHash;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

pub fn word(value: usize) -> [u8; 4] {
    u32::try_from(value)
        .expect("Bounded proof dimension")
        .to_le_bytes()
}
pub fn framed(parts: &[&[u8]]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(&word(part.len()));
        bytes.extend_from_slice(part);
    }
    bytes
}
pub fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut state = ProtocolHash::new();
    for part in std::iter::once(domain).chain(parts.iter().copied()) {
        state.update(word(part.len()));
        state.update(part);
    }
    state.finalize()
}
fn shake(parts: &[&[u8]], length: usize) -> Vec<u8> {
    let mut state = Shake256::default();
    for part in parts {
        state.update(&word(part.len()));
        state.update(part);
    }
    let mut result = vec![0; length];
    state.finalize_xof().read(&mut result);
    result
}
pub struct Transcript<'a> {
    role: &'a [u8],
    context: &'a [u8; 64],
    state: Vec<u8>,
    message: Vec<u8>,
    pub round: usize,
}
impl<'a> Transcript<'a> {
    pub fn new(role: &'a [u8], context: &'a [u8; 64], length: usize) -> Self {
        let mut transcript = Self {
            role,
            context,
            state: vec![0; length],
            message: Vec::new(),
            round: 0,
        };
        transcript.refresh();
        transcript
    }
    fn refresh(&mut self) {
        self.message = shake(
            &[
                b"compact-proof/verifier-message",
                self.role,
                self.context,
                &self.state,
                &word(self.round),
            ],
            self.state.len(),
        );
    }
    pub fn respond(&mut self, salt: &[u8], parts: &[&[u8]]) {
        assert_eq!(salt.len(), 128);
        let round = word(self.round);
        let mut inputs: Vec<&[u8]> = vec![self.role, self.context, &round, salt];
        inputs.extend_from_slice(parts);
        let digest = hash(b"compact-proof/message-root", &inputs);
        let tail = shake(
            &[
                b"compact-proof/chain-state",
                self.role,
                self.context,
                &self.message,
                &digest,
            ],
            self.state.len(),
        );
        self.state[..64].copy_from_slice(&digest);
        let length = self.state.len();
        self.state[64..].copy_from_slice(&tail[..length - 64]);
        self.round += 1;
        self.refresh();
    }
    pub fn challenge(&self, index: usize, nonbase: bool) -> Element {
        std::array::from_fn(|coordinate| {
            let bytes =
                &self.message[96 * index + 32 * coordinate..96 * index + 32 * (coordinate + 1)];
            let modulus = if nonbase && coordinate == 2 {
                MODULUS - 1
            } else {
                MODULUS
            };
            let value =
                num_bigint::BigUint::from_bytes_le(bytes) % num_bigint::BigUint::from(modulus);
            let mut encoded = [0; 16];
            let reduced = value.to_bytes_le();
            encoded[..reduced.len()].copy_from_slice(&reduced);
            u128::from_le_bytes(encoded) + u128::from(nonbase && coordinate == 2)
        })
    }
    pub fn positions(&self, offset: usize, count: usize, domain: usize) -> Vec<usize> {
        (0..count)
            .map(|index| {
                u32::from_le_bytes(
                    self.message[offset + 4 * index..offset + 4 * (index + 1)]
                        .try_into()
                        .unwrap(),
                ) as usize
                    % domain
            })
            .collect()
    }
}
