#![deny(unsafe_op_in_unsafe_fn)]
#[path = "../../word-proof/src/combination.rs"]
pub mod combination;
mod convolution;
#[path = "../../word-proof/src/field.rs"]
pub mod field;
#[path = "../../word-proof/src/fri.rs"]
pub mod fri;
#[path = "../../registration-proof/src/linear.rs"]
pub mod linear;
#[path = "../../word-proof/src/linear-oracle.rs"]
pub mod linear_oracle;
#[path = "../../word-proof/src/oracles.rs"]
pub mod oracles;
pub mod parameters;
pub mod proof;
#[path = "../../word-proof/src/random.rs"]
mod random;
#[cfg(any(target_arch = "wasm32", test))]
#[path = "release-entropy.rs"]
pub mod release_entropy;
pub mod statement;
use field::base as arithmetic;
#[path = "../../word-verifier/src/engine.rs"]
mod engine;
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};
#[path = "../../word-proof/src/transcript.rs"]
pub mod transcript;
#[path = "../../word-proof/src/tree.rs"]
pub mod tree;
mod witness;
use statement::{StatementOutput, StatementStream};
use supported_profile::{Profile, relation::release_relation};
pub use witness::{
    PreparedRelease, ReleaseInputError, ReleaseInputs, derive_bound, noise_random_bytes,
};

impl engine::Statement for StatementStream {
    fn push(&mut self, bytes: &[u8]) -> bool {
        StatementStream::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<StatementOutput> {
        StatementStream::finish(self).ok()
    }
}

pub type Verifier = engine::Verifier<StatementStream>;
impl Verifier {
    /// Verifies one profile's release proof against its expected statement.
    pub fn new(
        profile: Profile,
        role: &[u8],
        expected_statement: [u8; 64],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        Self::open(
            release_relation(profile),
            role,
            expected_statement,
            proof_header,
            |alpha, queries| StatementStream::new(profile, expected_statement, alpha, queries).ok(),
        )
    }
}
