use crate::{
    field::{Element, MODULUS, ZERO},
    parameters::*,
};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use stateful_sha3::{Digest, Sha3_512};
use std::{fs::File, io::Read, path::Path};

pub fn part(state: &mut Sha3_512, bytes: &[u8]) {
    Digest::update(state, (bytes.len() as u32).to_le_bytes());
    Digest::update(state, bytes);
}
pub fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut state = Sha3_512::new();
    part(&mut state, domain);
    for value in parts {
        part(&mut state, value);
    }
    state.finalize().into()
}
fn wide(domain: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut state = Shake256::default();
    Update::update(&mut state, &(domain.len() as u32).to_le_bytes());
    Update::update(&mut state, domain);
    for value in parts {
        Update::update(&mut state, &(value.len() as u32).to_le_bytes());
        Update::update(&mut state, value);
    }
    let mut result = vec![0; MESSAGE_BYTES];
    XofReader::read(&mut state.finalize_xof(), &mut result);
    result
}
pub fn parameters() -> Vec<u8> {
    let values = relation_parameters();
    let mut bytes: Vec<u8> = values
        .into_iter()
        .chain(degrees())
        .flat_map(|value| (value as u32).to_le_bytes())
        .collect();
    for index in 0..LOOKUPS {
        let (column, scale) = lookup(index);
        bytes.extend((column as u32).to_le_bytes());
        bytes.extend((scale as u32).to_le_bytes());
    }
    bytes
}
pub fn context(directory: &Path, role: &[u8], expected_statement: &[u8; 64]) -> [u8; 64] {
    let mut state = context_hasher(role);
    let length = statement_length();
    let mut statement = Sha3_512::new();
    let mut total = 0;
    let mut bytes = vec![0; 1 << 20];
    for index in 0..STATEMENT_PARTS {
        let name = if index == 0 {
            "header.bin".to_owned()
        } else {
            format!("polynomial-{:02}.bin", index - 1)
        };
        let mut file = File::open(directory.join(name)).unwrap();
        loop {
            let length = file.read(&mut bytes).unwrap();
            if length == 0 {
                break;
            }
            Digest::update(&mut state, &bytes[..length]);
            Digest::update(&mut statement, &bytes[..length]);
            total += length;
        }
    }
    assert_eq!(total, length);
    assert_eq!(<[u8; 64]>::from(statement.finalize()), *expected_statement);
    state.finalize().into()
}
pub fn statement_length() -> usize {
    STATEMENT_BYTES
}
pub fn context_hasher(role: &[u8]) -> Sha3_512 {
    let mut state = Sha3_512::new();
    part(&mut state, b"bounded-proof/statement");
    for value in [
        role,
        RELATION_TAG,
        &2u128.to_le_bytes(),
        &crate::field::root(1 << 20).to_le_bytes(),
        &7u128.to_le_bytes(),
        &parameters(),
        &(MODULUS - 1).to_le_bytes(),
    ] {
        part(&mut state, value);
    }
    Digest::update(&mut state, (statement_length() as u32).to_le_bytes());
    state
}
pub struct Transcript {
    pub role: Vec<u8>,
    pub context: [u8; 64],
    state: Vec<u8>,
    pub message: Vec<u8>,
    pub salts: Vec<[u8; 128]>,
    pub round: u32,
}
impl Transcript {
    pub fn new(role: &[u8], context: [u8; 64]) -> Self {
        Self {
            role: role.to_vec(),
            context,
            state: vec![0; MESSAGE_BYTES],
            message: Vec::new(),
            salts: Vec::new(),
            round: 0,
        }
    }
    pub fn next(&mut self) {
        self.round += 1;
        self.message = wide(
            b"bounded-proof/verifier-message",
            &[
                &self.role,
                &self.context,
                &self.state,
                &self.round.to_le_bytes(),
            ],
        );
    }
    pub fn respond(&mut self, parts: &[&[u8]]) {
        let mut salt = [0; 128];
        crate::random::fill(&mut salt);
        self.respond_with_salt(parts, salt);
    }
    pub fn respond_with_salt(&mut self, parts: &[&[u8]], salt: [u8; 128]) {
        let round = self.round.to_le_bytes();
        let mut inputs = vec![
            self.role.as_slice(),
            self.context.as_slice(),
            round.as_slice(),
            salt.as_slice(),
        ];
        inputs.extend_from_slice(parts);
        let root = hash(b"bounded-proof/message-root", &inputs);
        let digest = wide(
            b"bounded-proof/chain-state",
            &[&self.role, &self.context, &self.message, &root],
        );
        self.state[..64].copy_from_slice(&root);
        self.state[64..].copy_from_slice(&digest[..MESSAGE_BYTES - 64]);
        self.salts.push(salt);
    }
}
fn reduce(bytes: &[u8], modulus: u128) -> u128 {
    let mut remainder = 0;
    for byte in bytes.iter().rev() {
        for bit in (0..8).rev() {
            let complement = modulus - remainder;
            remainder = if remainder >= complement {
                remainder - complement
            } else {
                remainder + remainder
            };
            if (byte >> bit) & 1 != 0 {
                remainder = if remainder == modulus - 1 {
                    0
                } else {
                    remainder + 1
                };
            }
        }
    }
    remainder
}
pub fn challenge(message: &[u8], index: usize, nonbase: bool) -> Element {
    let bytes = &message[96 * index..96 * (index + 1)];
    let mut value = ZERO;
    for (coordinate, entry) in value.iter_mut().enumerate() {
        let nonzero = nonbase && coordinate == 2;
        *entry = reduce(
            &bytes[32 * coordinate..32 * (coordinate + 1)],
            if nonzero { MODULUS - 1 } else { MODULUS },
        );
        if nonzero {
            *entry += 1;
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_unused_message_bytes_bind_the_next_state() {
        let mut left = Transcript::new(b"test", [3; 64]);
        let mut right = Transcript::new(b"test", [3; 64]);
        left.next();
        right.next();
        right.message[MESSAGE_BYTES - 1] ^= 1;
        assert_eq!(
            challenge(&left.message, 0, false),
            challenge(&right.message, 0, false)
        );
        left.respond_with_salt(&[b"root"], [7; 128]);
        right.respond_with_salt(&[b"root"], [7; 128]);
        left.next();
        right.next();
        assert_ne!(left.message, right.message);
    }
}
