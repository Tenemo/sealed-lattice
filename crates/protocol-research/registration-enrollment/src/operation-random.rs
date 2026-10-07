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
    use zeroize::Zeroize;

    thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}

    /// Whether the purpose's randomness is installed from its seed and
    /// undrawn, so that the operation draws only from that seed.
    pub fn ready(purpose: Purpose) -> bool {
        STATE.with(|state| state.borrow().ready(purpose))
    }

    /// The completed setup retires the contribution's remaining private
    /// stream state along with its persisted seed and witness records.
    pub fn retire_contribution() {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            if state
                .streams
                .as_ref()
                .is_some_and(|streams| streams.purpose == Purpose::Contribution)
            {
                state.streams = None;
                state.input.zeroize();
                state.output.zeroize();
            }
        });
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
pub use browser::{ready, retire_contribution};

#[cfg(test)]
#[path = "operation-random-tests.rs"]
mod tests;
