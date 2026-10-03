#![deny(unsafe_op_in_unsafe_fn)]
pub mod parameters;
pub mod proof;
pub mod statement;
#[cfg(test)]
#[path = "zero-product-tests.rs"]
mod zero_product_tests;
use setup_stream_kernel::SetupStatementOutput;
use statement::StatementStream;
use supported_profile::relation::registration_relation;
use word_verifier::engine;
pub use word_verifier::engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};

impl engine::Statement for StatementStream {
    fn push(&mut self, bytes: &[u8]) -> bool {
        StatementStream::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<SetupStatementOutput> {
        StatementStream::finish(self).ok()
    }
}

pub type Verifier = engine::Verifier<StatementStream>;
/// Verifies a registration key proof. Registration precedes the roster, so
/// every profile shares its relation.
pub fn verifier(
    role: &[u8],
    expected_statement: [u8; 64],
    proof_header: &[u8],
) -> Result<Verifier, Refusal> {
    Verifier::open(
        registration_relation(),
        role,
        expected_statement,
        proof_header,
        |alpha, queries| StatementStream::new(expected_statement, alpha, queries).ok(),
    )
}
