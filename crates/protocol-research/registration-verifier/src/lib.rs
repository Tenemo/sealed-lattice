#![deny(unsafe_op_in_unsafe_fn)]
#[path = "../../setup-stream-kernel/src/arithmetic.rs"]
mod arithmetic;
#[path = "../../word-verifier/src/engine.rs"]
mod engine;
mod profile;
mod statement {
    pub use registration_proof::statement::StatementStream;
    pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
}
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal, Verifier};
