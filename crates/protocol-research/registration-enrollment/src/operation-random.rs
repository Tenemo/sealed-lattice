//! The private randomness of one participant operation, expanded from a seed
//! the worker retains before that operation draws any byte: a contribution
//! generation or continuation, a ballot, or a release. An interrupted
//! operation installs the same seed again and draws the same bytes in the
//! same order, so it reproduces its outputs exactly instead of sampling anew.
//! Each seed yields the operation's streams: SHAKE256 over the canonical
//! foundation tuple of the stream's domain and the seed, whose first 64 bytes
//! are the foundation hash of that tuple. While a seed is installed, its
//! streams serve the operation's draws within the module.

use parallel_work::random;
use registration_credentials::foundation::{
    CANONICAL_TUPLE_SCHEMA_IDENTIFIER, CANONICAL_TUPLE_VERSION, CanonicalItem, CanonicalItemType,
};
use sha3::{
    Shake256, Shake256Reader,
    digest::{ExtendableOutput, Update, XofReader},
};
use zeroize::{Zeroize, Zeroizing};

const SEED_BYTES: usize = 64;

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
    /// The draws the first stream serves.
    fn first(self) -> Option<random::Purpose> {
        match self {
            Self::Contribution => Some(random::Purpose::Witness),
            Self::Ballot => Some(random::Purpose::Ballot),
            Self::Release => None,
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
}

struct State {
    input: Zeroizing<[u8; SEED_BYTES]>,
    streams: Option<Streams>,
    // The bytes each stream of the last installed seed served.
    drawn: [usize; 2],
}
impl Default for State {
    fn default() -> Self {
        Self {
            input: Zeroizing::new([0; SEED_BYTES]),
            streams: None,
            drawn: [0; 2],
        }
    }
}
impl State {
    /// Operations zero, four and five install the seed in the input for a
    /// contribution, a ballot or a release, and three discards the streams.
    /// Every call clears the input.
    fn command(&mut self, operation: u32, length: usize) -> Result<(), ()> {
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
                });
                self.drawn = [0; 2];
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
    /// Serves a draw of the installed operation: its first stream serves the
    /// draws of its first purpose and its proof stream every proof. Any other
    /// draw is refused.
    fn serve(&mut self, purpose: random::Purpose, bytes: &mut [u8]) -> bool {
        let Some(streams) = self.streams.as_mut() else {
            return false;
        };
        let stream = if purpose == random::Purpose::Proof {
            1
        } else if streams.purpose.first() == Some(purpose) {
            0
        } else {
            return false;
        };
        let Some(reader) = streams.readers[stream].as_mut() else {
            return false;
        };
        reader.read(bytes);
        self.drawn[stream] += bytes.len();
        true
    }
    /// Whether the purpose's streams are installed and nothing was read.
    fn ready(&self, purpose: Purpose) -> bool {
        self.streams
            .as_ref()
            .is_some_and(|streams| streams.purpose == purpose)
            && self.drawn == [0; 2]
    }
}

#[cfg(target_arch = "wasm32")]
mod browser {
    use super::{Purpose, State};
    use parallel_work::random;
    use std::cell::RefCell;
    use zeroize::Zeroize;

    thread_local! {static STATE:RefCell<State>=RefCell::new(State::default());}

    fn serve(purpose: random::Purpose, bytes: &mut [u8]) -> bool {
        STATE.with(|state| state.borrow_mut().serve(purpose, bytes))
    }

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
                random::release();
            }
        });
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn operation_random_input_pointer() -> usize {
        STATE.with(|state| state.borrow_mut().input.as_mut_ptr() as usize)
    }
    /// The bytes the first or the proof stream of the last installed seed
    /// served.
    #[unsafe(no_mangle)]
    pub extern "C" fn operation_random_drawn(stream: u32) -> usize {
        STATE.with(|state| state.borrow().drawn[stream as usize])
    }
    /// While a seed's streams are installed, they serve the operation's
    /// draws.
    #[unsafe(no_mangle)]
    pub extern "C" fn operation_random_command(operation: u32, length: usize) -> u32 {
        STATE.with(|state| {
            let mut state = state.borrow_mut();
            let installed = state.streams.is_some();
            let refused = state.command(operation, length).is_err();
            match (installed, state.streams.is_some()) {
                (false, true) => random::install(serve),
                (true, false) => random::release(),
                _ => {}
            }
            u32::from(refused)
        })
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::{ready, retire_contribution};

#[cfg(test)]
#[path = "operation-random-tests.rs"]
mod tests;
