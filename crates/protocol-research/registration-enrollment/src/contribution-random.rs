//! The private randomness of one contribution generation or continuation,
//! expanded from a seed the worker retains before that operation draws any
//! byte. An interrupted operation installs the same seed again and draws the
//! same bytes in the same order, so it reproduces its outputs exactly instead
//! of sampling anew. Each seed yields a witness stream and a proof stream:
//! SHAKE256 over the canonical foundation tuple of the stream's domain and the
//! seed, whose first 64 bytes are the foundation hash of that tuple.

use registration_credentials::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalItemType,
};
use sha3::{
    Shake256, Shake256Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::{Zeroize, Zeroizing};

const SEED_BYTES: usize = 64;
const REQUEST_BYTES: usize = 65_536;
const WITNESS_DOMAIN: &str = "sealed-lattice/contribution-witness-randomness/v1";
const PROOF_DOMAIN: &str = "sealed-lattice/contribution-proof-randomness/v1";

// Absorbs the canonical tuple of the domain and the seed as one raw byte
// item, as the foundation hash frames it, without copying the seed.
fn stream(domain: &str, seed: &[u8; SEED_BYTES]) -> Shake256Reader {
    let domain =
        CanonicalItem::nonempty_ascii(domain).expect("A stream domain is canonical ASCII.");
    let mut hasher = Shake256::default();
    hasher.update(&CANONICAL_TUPLE_SCHEMA_IDENTIFIER.to_le_bytes());
    hasher.update(&CANONICAL_TUPLE_VERSION.to_le_bytes());
    hasher.update(&2_u32.to_le_bytes());
    hasher.update(&domain.item_type().canonical_code().to_le_bytes());
    hasher.update(&(domain.canonical_bytes().len() as u32).to_le_bytes());
    hasher.update(domain.canonical_bytes());
    hasher.update(&CanonicalItemType::RawBytes.canonical_code().to_le_bytes());
    hasher.update(&(SEED_BYTES as u32 + 4).to_le_bytes());
    hasher.update(&(SEED_BYTES as u32).to_le_bytes());
    hasher.update(seed);
    hasher.finalize_xof()
}

struct State {
    input: Zeroizing<[u8; SEED_BYTES]>,
    output: Zeroizing<Vec<u8>>,
    // The witness stream, then the proof stream, of the installed seed.
    streams: Option<[Shake256Reader; 2]>,
}
impl Default for State {
    fn default() -> Self {
        Self {
            input: Zeroizing::new([0; SEED_BYTES]),
            output: Zeroizing::new(vec![0; REQUEST_BYTES]),
            streams: None,
        }
    }
}
impl State {
    /// Operation zero installs the seed in the input, one and two write the
    /// next `length` bytes of the witness or proof stream to the output, and
    /// three discards the streams. Every call clears the previous output and
    /// the input.
    fn command(&mut self, operation: u32, length: usize) -> Result<(), ()> {
        self.output.as_mut_slice().zeroize();
        let result = self.command_inner(operation, length);
        self.input.zeroize();
        result
    }
    fn command_inner(&mut self, operation: u32, length: usize) -> Result<(), ()> {
        match operation {
            0 => {
                if self.streams.is_some() || length != SEED_BYTES {
                    return Err(());
                }
                self.streams = Some([
                    stream(WITNESS_DOMAIN, &self.input),
                    stream(PROOF_DOMAIN, &self.input),
                ]);
            }
            1 | 2 => {
                let streams = self.streams.as_mut().ok_or(())?;
                if !(1..=REQUEST_BYTES).contains(&length) {
                    return Err(());
                }
                streams[operation as usize - 1].read(&mut self.output[..length]);
            }
            3 => {
                if length != 0 {
                    return Err(());
                }
                self.streams = None;
            }
            _ => return Err(()),
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::State;
    use std::cell::RefCell;

    thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}

    #[unsafe(no_mangle)]
    pub extern "C" fn contribution_random_input_pointer() -> usize {
        STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn contribution_random_output_pointer() -> usize {
        STATE.with(|state| state.borrow().output.as_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn contribution_random_command(operation: u32, length: usize) -> u32 {
        STATE.with(|state| u32::from(state.borrow_mut().command(operation, length).is_err()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registration_credentials::foundation::hash_foundation_tuple_512;

    fn seed(first: u8) -> [u8; SEED_BYTES] {
        std::array::from_fn(|index| first.wrapping_add((index * 29) as u8))
    }

    fn install(state: &mut State, seed: &[u8; SEED_BYTES]) {
        state.input.copy_from_slice(seed);
        state.command(0, SEED_BYTES).unwrap();
        assert!(state.input.iter().all(|value| *value == 0));
    }

    // Reads the whole stream prefix through requests of the given lengths.
    fn read(state: &mut State, operation: u32, lengths: &[usize]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for &length in lengths {
            state.command(operation, length).unwrap();
            bytes.extend_from_slice(&state.output[..length]);
        }
        bytes
    }

    #[test]
    fn frames_each_stream_as_the_foundation_hash_of_its_domain_and_seed() {
        let seed = seed(3);
        let mut state = State::default();
        install(&mut state, &seed);
        for (operation, domain) in [(1, WITNESS_DOMAIN), (2, PROOF_DOMAIN)] {
            let expected =
                hash_foundation_tuple_512(domain, &[CanonicalItem::variable_bytes(seed).unwrap()])
                    .unwrap()
                    .into_bytes();
            assert_eq!(read(&mut state, operation, &[64]), expected);
        }
    }

    #[test]
    fn replays_the_same_bytes_whatever_the_request_lengths_and_interleaving() {
        let seed = seed(11);
        let mut first = State::default();
        install(&mut first, &seed);
        let witness = read(&mut first, 1, &[1, 17, REQUEST_BYTES, 3]);
        let proof = read(&mut first, 2, &[REQUEST_BYTES - 1, 2]);
        // A restarted operation reads both streams again in another order.
        let mut restarted = State::default();
        install(&mut restarted, &seed);
        assert_eq!(read(&mut restarted, 2, &[REQUEST_BYTES, 1]), proof);
        assert_eq!(read(&mut restarted, 1, &[REQUEST_BYTES, 21]), witness);
        assert_ne!(witness[..64], proof[..64]);
        // A seed that differs in its last bit yields other streams.
        let mut changed = seed;
        changed[SEED_BYTES - 1] ^= 1;
        let mut other = State::default();
        install(&mut other, &changed);
        assert_ne!(read(&mut other, 1, &[64]), witness[..64]);
    }

    #[test]
    fn refuses_reads_without_a_seed_oversized_requests_and_a_second_seed() {
        let mut state = State::default();
        assert!(state.command(1, 1).is_err());
        assert!(state.command(0, SEED_BYTES - 1).is_err());
        install(&mut state, &seed(5));
        assert!(state.command(0, SEED_BYTES).is_err());
        assert!(state.command(1, 0).is_err());
        assert!(state.command(2, REQUEST_BYTES + 1).is_err());
        assert!(state.command(4, 1).is_err());
        state.command(1, 8).unwrap();
        // A refused command clears the previous output.
        assert!(state.command(3, 1).is_err());
        assert!(state.output.iter().all(|value| *value == 0));
        state.command(3, 0).unwrap();
        assert!(state.streams.is_none());
        assert!(state.command(2, 1).is_err());
    }
}
