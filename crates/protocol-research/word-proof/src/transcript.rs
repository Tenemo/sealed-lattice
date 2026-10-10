use crate::field::{Element, MODULUS, ZERO};
use parallel_work::ProtocolHash;
use parallel_work::{HashStream, Sponge};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use supported_profile::relation::*;

pub fn part(state: &mut ProtocolHash, bytes: &[u8]) {
    state.update((bytes.len() as u32).to_le_bytes());
    state.update(bytes);
}
pub fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut state = ProtocolHash::new();
    part(&mut state, domain);
    for value in parts {
        part(&mut state, value);
    }
    state.finalize()
}
fn wide(domain: &[u8], parts: &[&[u8]], length: usize) -> Vec<u8> {
    let mut state = Shake256::default();
    Update::update(&mut state, &(domain.len() as u32).to_le_bytes());
    Update::update(&mut state, domain);
    for value in parts {
        Update::update(&mut state, &(value.len() as u32).to_le_bytes());
        Update::update(&mut state, value);
    }
    let mut result = vec![0; length];
    XofReader::read(&mut state.finalize_xof(), &mut result);
    result
}
pub fn parameters(relation: &Relation) -> Vec<u8> {
    let mut bytes: Vec<u8> = relation
        .relation_parameters()
        .into_iter()
        .chain(relation.degrees())
        .flat_map(|value| (value as u32).to_le_bytes())
        .collect();
    for index in 0..relation.lookups() {
        let (column, scale) = relation.lookup(index);
        bytes.extend((column as u32).to_le_bytes());
        bytes.extend((scale as u32).to_le_bytes());
    }
    bytes
}
/// The statement context before the statement bytes, which the caller
/// appends.
pub fn context_hasher(relation: &Relation, role: &[u8]) -> ProtocolHash {
    let mut state = ProtocolHash::new();
    context_prefix(relation, role, |bytes| state.update(bytes));
    state
}
/// The same context as a stream, which a helper hashes when there are
/// helpers.
pub fn context_stream(relation: &Relation, role: &[u8]) -> HashStream {
    let mut stream = HashStream::new(Sponge::ProtocolHash);
    context_prefix(relation, role, |bytes| stream.update(bytes));
    stream
}
// The context's bytes before the statement: each part after its length,
// then the statement's length.
fn context_prefix(relation: &Relation, role: &[u8], mut absorb: impl FnMut(&[u8])) {
    for value in [
        b"bounded-proof/statement".as_slice(),
        role,
        relation.tag,
        &2u128.to_le_bytes(),
        &crate::field::root(1 << 20).to_le_bytes(),
        &7u128.to_le_bytes(),
        &parameters(relation),
        &(MODULUS - 1).to_le_bytes(),
    ] {
        absorb(&(value.len() as u32).to_le_bytes());
        absorb(value);
    }
    absorb(&(relation.statement_bytes() as u32).to_le_bytes());
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
    /// Verifier messages and chained states have the relation's message
    /// length.
    pub fn new(role: &[u8], context: [u8; 64], message_bytes: usize) -> Self {
        Self {
            role: role.to_vec(),
            context,
            state: vec![0; message_bytes],
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
            self.state.len(),
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
        let length = self.state.len();
        let digest = wide(
            b"bounded-proof/chain-state",
            &[&self.role, &self.context, &self.message, &root],
            length,
        );
        self.state[..64].copy_from_slice(&root);
        self.state[64..].copy_from_slice(&digest[..length - 64]);
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
#[path = "transcript-tests.rs"]
mod tests;
