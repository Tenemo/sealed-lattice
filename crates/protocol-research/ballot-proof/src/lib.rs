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
/// Verifies one profile's ballot proof.
pub fn verifier(profile: Profile, role: &[u8], proof_header: &[u8]) -> Result<Verifier, Refusal> {
    Verifier::open(
        ballot_relation(profile),
        role,
        proof_header,
        |statement, alpha, queries| StatementStream::new(profile, statement, alpha, queries).ok(),
    )
}
