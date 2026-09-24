#![deny(unsafe_op_in_unsafe_fn)]
pub mod admission;
pub mod body;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "body-browser.rs"]
mod body_browser;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
mod browser;
pub mod close;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "close-browser.rs"]
mod close_browser;
pub mod columns;
pub mod context;
#[path = "../../word-proof/src/field.rs"]
pub mod field;
#[path = "../../word-proof/src/oracles.rs"]
pub mod oracles;
pub mod parameters;
#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
#[path = "prover-browser.rs"]
mod prover_browser;
#[path = "../../word-proof/src/random.rs"]
mod random;
pub mod statement;
pub mod submission;
#[path = "../../word-proof/src/transcript.rs"]
pub mod transcript;
#[path = "../../word-proof/src/tree.rs"]
pub mod tree;
use field::base as arithmetic;
#[path = "../../word-proof/src/combination.rs"]
pub mod combination;
#[path = "../../word-verifier/src/engine.rs"]
mod engine;
#[path = "../../word-proof/src/fri.rs"]
pub mod fri;
#[path = "../../registration-proof/src/linear.rs"]
pub mod linear;
#[path = "../../word-proof/src/linear-oracle.rs"]
pub mod linear_oracle;
#[path = "private-ballot.rs"]
pub mod private_ballot;
pub mod proof;
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};
use statement::{StatementOutput, StatementStream};
use supported_profile::{Profile, relation::ballot_relation};

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
    /// Verifies one profile's ballot proof against its expected statement.
    pub fn new(
        profile: Profile,
        role: &[u8],
        expected_statement: [u8; 64],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        Self::open(
            ballot_relation(profile),
            role,
            expected_statement,
            proof_header,
            |alpha, queries| StatementStream::new(profile, expected_statement, alpha, queries).ok(),
        )
    }
}

#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
pub fn take_browser_classification() -> Option<body::BallotBodyClassification> {
    body_browser::take_classification()
}

#[cfg(all(target_arch = "wasm32", feature = "bridge"))]
pub fn take_browser_close_barrier() -> Option<close::VerifiedCloseBarrier> {
    close_browser::take_barrier()
}
