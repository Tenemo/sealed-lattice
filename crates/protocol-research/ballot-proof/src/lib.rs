#![deny(unsafe_op_in_unsafe_fn)]
pub mod body;
#[path = "classification-session.rs"]
pub mod classification_session;
pub mod columns;
pub mod context;
#[path = "private-ballot.rs"]
pub mod private_ballot;
pub mod proof;
pub mod statement;
pub mod submission;
use statement::StatementStream;
use supported_profile::{Profile, relation::ballot_relation};
use word_verifier::engine;
pub use word_verifier::engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};

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
