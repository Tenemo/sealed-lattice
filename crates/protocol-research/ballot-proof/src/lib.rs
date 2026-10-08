#![deny(unsafe_op_in_unsafe_fn)]
pub mod admission;
pub mod body;
#[cfg(target_arch = "wasm32")]
#[path = "body-browser.rs"]
mod body_browser;
pub mod columns;
pub mod context;
#[path = "private-ballot.rs"]
pub mod private_ballot;
pub mod proof;
pub mod statement;
pub mod submission;
use statement::{StatementOutput, StatementStream};
use supported_profile::{Profile, relation::ballot_relation};
use word_verifier::engine;
pub use word_verifier::engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};

impl engine::Statement for StatementStream {
    fn push(&mut self, bytes: &[u8]) -> bool {
        StatementStream::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<StatementOutput> {
        StatementStream::finish(self).ok()
    }
}

pub type Verifier = engine::Verifier<StatementStream>;
/// Verifies one profile's ballot proof against its expected statement.
pub fn verifier(
    profile: Profile,
    role: &[u8],
    expected_statement: [u8; 64],
    proof_header: &[u8],
) -> Result<Verifier, Refusal> {
    Verifier::open(
        ballot_relation(profile),
        role,
        expected_statement,
        proof_header,
        |alpha, queries| StatementStream::new(profile, expected_statement, alpha, queries).ok(),
    )
}

#[cfg(target_arch = "wasm32")]
pub fn take_browser_classification() -> Option<body::BallotBodyClassification> {
    body_browser::take_classification()
}

/// Releases the statement inputs that the classified ballots shared.
#[cfg(target_arch = "wasm32")]
pub fn release_browser_ballot_inputs() {
    body_browser::release_inputs()
}
