#![deny(unsafe_op_in_unsafe_fn)]
pub mod engine;
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};
use statement_stream::{SetupStatementStream, StatementOutput};
use supported_profile::{Profile, relation::setup_relation};

impl engine::Statement for SetupStatementStream {
    fn push(&mut self, bytes: &[u8]) -> bool {
        SetupStatementStream::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<StatementOutput> {
        SetupStatementStream::finish(self).ok()
    }
}

pub type Verifier = engine::Verifier<SetupStatementStream>;
/// Verifies a complete setup contribution proof of one profile.
pub fn verifier(
    profile: Profile,
    role: &[u8],
    expected_statement: [u8; 64],
    proof_header: &[u8],
) -> Result<Verifier, Refusal> {
    Verifier::open(
        setup_relation(profile),
        role,
        expected_statement,
        proof_header,
        |alpha, queries| {
            SetupStatementStream::new(profile, expected_statement, alpha, queries).ok()
        },
    )
}

#[cfg(test)]
#[path = "lib-tests.rs"]
mod tests;
