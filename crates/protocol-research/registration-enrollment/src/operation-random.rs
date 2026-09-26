//! The private randomness of one participant operation, expanded from a seed
//! the worker retains before that operation draws any byte: a contribution
//! generation or continuation, a ballot, or a release. An interrupted
//! operation installs the same seed again and draws the same bytes in the
//! same order, so it reproduces its outputs exactly instead of sampling anew.
//! Each seed yields the operation's streams: SHAKE256 over the canonical
//! foundation tuple of the stream's domain and the seed, whose first 64 bytes
//! are the foundation hash of that tuple.

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

/// The operations whose randomness a retained seed supplies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Contribution,
    Ballot,
    Release,
}
impl Purpose {
    /// The domain of the operation's first stream, if it has one, and of its
    /// proof stream: a contribution's witnesses, a ballot's encryptions, and
    /// a release, which draws only proof randomness.
    fn domains(self) -> [Option<&'static str>; 2] {
        match self {
            Self::Contribution => [
                Some("sealed-lattice/contribution-witness-randomness/v1"),
                Some("sealed-lattice/contribution-proof-randomness/v1"),
            ],
            Self::Ballot => [
                Some("sealed-lattice/ballot-encryption-randomness/v1"),
                Some("sealed-lattice/ballot-proof-randomness/v1"),
            ],
            Self::Release => [None, Some("sealed-lattice/release-proof-randomness/v1")],
        }
    }
}

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

struct Streams {
    purpose: Purpose,
    readers: [Option<Shake256Reader>; 2],
    // Whether any byte of either stream was read.
    drawn: bool,
}

struct State {
    input: Zeroizing<[u8; SEED_BYTES]>,
    output: Zeroizing<Vec<u8>>,
    streams: Option<Streams>,
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
    /// Operations zero, four and five install the seed in the input for a
    /// contribution, a ballot or a release; one and two write the next
    /// `length` bytes of the first or the proof stream to the output; three
    /// discards the streams. Every call clears the previous output and the
    /// input.
    fn command(&mut self, operation: u32, length: usize) -> Result<(), ()> {
        self.output.as_mut_slice().zeroize();
        let result = self.command_inner(operation, length);
        self.input.zeroize();
        result
    }
    fn command_inner(&mut self, operation: u32, length: usize) -> Result<(), ()> {
        match operation {
            0 | 4 | 5 => {
                if self.streams.is_some() || length != SEED_BYTES {
                    return Err(());
                }
                let purpose = match operation {
                    0 => Purpose::Contribution,
                    4 => Purpose::Ballot,
                    _ => Purpose::Release,
                };
                let seed = &self.input;
                self.streams = Some(Streams {
                    purpose,
                    readers: purpose
                        .domains()
                        .map(|domain| domain.map(|domain| stream(domain, seed))),
                    drawn: false,
                });
            }
            1 | 2 => {
                let streams = self.streams.as_mut().ok_or(())?;
                let reader = streams.readers[operation as usize - 1].as_mut().ok_or(())?;
                if !(1..=REQUEST_BYTES).contains(&length) {
                    return Err(());
                }
                reader.read(&mut self.output[..length]);
                streams.drawn = true;
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
    /// Whether the purpose's streams are installed and nothing was read.
    fn ready(&self, purpose: Purpose) -> bool {
        self.streams
            .as_ref()
            .is_some_and(|streams| streams.purpose == purpose && !streams.drawn)
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::{Purpose, State};
    use std::cell::RefCell;

    thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}

    /// Whether the purpose's randomness is installed from its seed and
    /// undrawn, so that the operation draws only from that seed.
    pub fn ready(purpose: Purpose) -> bool {
        STATE.with(|state| state.borrow().ready(purpose))
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn operation_random_input_pointer() -> usize {
        STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn operation_random_output_pointer() -> usize {
        STATE.with(|state| state.borrow().output.as_ptr() as usize)
    }
    #[unsafe(no_mangle)]
    pub extern "C" fn operation_random_command(operation: u32, length: usize) -> u32 {
        STATE.with(|state| u32::from(state.borrow_mut().command(operation, length).is_err()))
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::ready;

#[cfg(test)]
mod tests {
    use super::*;
    use registration_credentials::foundation::hash_foundation_tuple_512;

    fn seed(first: u8) -> [u8; SEED_BYTES] {
        std::array::from_fn(|index| first.wrapping_add((index * 29) as u8))
    }

    fn install(state: &mut State, operation: u32, seed: &[u8; SEED_BYTES]) {
        state.input.copy_from_slice(seed);
        state.command(operation, SEED_BYTES).unwrap();
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
        for (install_operation, purpose) in [
            (0, Purpose::Contribution),
            (4, Purpose::Ballot),
            (5, Purpose::Release),
        ] {
            let mut state = State::default();
            install(&mut state, install_operation, &seed);
            for (operation, domain) in [1, 2].into_iter().zip(purpose.domains()) {
                let Some(domain) = domain else {
                    assert!(state.command(operation, 64).is_err());
                    continue;
                };
                let expected = hash_foundation_tuple_512(
                    domain,
                    &[CanonicalItem::variable_bytes(seed).unwrap()],
                )
                .unwrap()
                .into_bytes();
                assert_eq!(read(&mut state, operation, &[64]), expected);
            }
        }
        // Every stream of every purpose has its own domain.
        let mut domains: Vec<_> = [Purpose::Contribution, Purpose::Ballot, Purpose::Release]
            .into_iter()
            .flat_map(|purpose| purpose.domains())
            .flatten()
            .collect();
        domains.sort_unstable();
        domains.dedup();
        assert_eq!(domains.len(), 5);
    }

    #[test]
    fn replays_the_same_bytes_whatever_the_request_lengths_and_interleaving() {
        let seed = seed(11);
        let mut first = State::default();
        install(&mut first, 4, &seed);
        let encryption = read(&mut first, 1, &[1, 17, REQUEST_BYTES, 3]);
        let proof = read(&mut first, 2, &[REQUEST_BYTES - 1, 2]);
        // A restarted operation reads both streams again in another order.
        let mut restarted = State::default();
        install(&mut restarted, 4, &seed);
        assert_eq!(read(&mut restarted, 2, &[REQUEST_BYTES, 1]), proof);
        assert_eq!(read(&mut restarted, 1, &[REQUEST_BYTES, 21]), encryption);
        assert_ne!(encryption[..64], proof[..64]);
        // A seed that differs in its last bit yields other streams.
        let mut changed = seed;
        changed[SEED_BYTES - 1] ^= 1;
        let mut other = State::default();
        install(&mut other, 4, &changed);
        assert_ne!(read(&mut other, 1, &[64]), encryption[..64]);
    }

    #[test]
    fn is_ready_only_for_its_installed_and_undrawn_purpose() {
        let mut state = State::default();
        assert!(!state.ready(Purpose::Release));
        install(&mut state, 5, &seed(7));
        assert!(state.ready(Purpose::Release));
        assert!(!state.ready(Purpose::Ballot));
        read(&mut state, 2, &[1]);
        assert!(!state.ready(Purpose::Release));
        state.command(3, 0).unwrap();
        install(&mut state, 5, &seed(7));
        assert!(state.ready(Purpose::Release));
    }

    #[test]
    fn refuses_reads_without_a_seed_oversized_requests_and_a_second_seed() {
        let mut state = State::default();
        assert!(state.command(1, 1).is_err());
        assert!(state.command(0, SEED_BYTES - 1).is_err());
        install(&mut state, 0, &seed(5));
        for operation in [0, 4, 5] {
            assert!(state.command(operation, SEED_BYTES).is_err());
        }
        assert!(state.command(1, 0).is_err());
        assert!(state.command(2, REQUEST_BYTES + 1).is_err());
        assert!(state.command(6, 1).is_err());
        state.command(1, 8).unwrap();
        // A refused command clears the previous output.
        assert!(state.command(3, 1).is_err());
        assert!(state.output.iter().all(|value| *value == 0));
        state.command(3, 0).unwrap();
        assert!(state.streams.is_none());
        assert!(state.command(2, 1).is_err());
    }
}
