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
use protocol_foundations::foundation::{
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

pub(crate) struct Streams {
    pub(crate) purpose: Purpose,
    readers: [Option<Shake256Reader>; 2],
}

pub(crate) struct State {
    pub(crate) input: Zeroizing<[u8; SEED_BYTES]>,
    pub(crate) streams: Option<Streams>,
    // The bytes each stream of the last installed seed served.
    pub(crate) drawn: [usize; 2],
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
    pub(crate) fn command(&mut self, operation: u32, length: usize) -> Result<(), ()> {
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
    pub(crate) fn serve(&mut self, purpose: random::Purpose, bytes: &mut [u8]) -> bool {
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
    pub(crate) fn ready(&self, purpose: Purpose) -> bool {
        self.streams
            .as_ref()
            .is_some_and(|streams| streams.purpose == purpose)
            && self.drawn == [0; 2]
    }
}

#[cfg(test)]
#[path = "operation-random-tests.rs"]
mod tests;
