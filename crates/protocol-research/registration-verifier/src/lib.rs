#![deny(unsafe_op_in_unsafe_fn)]
#[path = "../../setup-stream-kernel/src/arithmetic.rs"]
mod arithmetic;
#[path = "../../word-verifier/src/engine.rs"]
mod engine;
mod statement {
    pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
}
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};
use registration_proof::statement::StatementStream;
use statement::StatementOutput;
use supported_profile::relation::registration_relation;

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
    /// Verifies a registration key proof. Registration precedes the roster,
    /// so every profile shares its relation.
    pub fn new(
        role: &[u8],
        expected_statement: [u8; 64],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        Self::open(
            registration_relation(),
            role,
            expected_statement,
            proof_header,
            |alpha, queries| StatementStream::new(expected_statement, alpha, queries).ok(),
        )
    }
}
