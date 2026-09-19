#![deny(unsafe_op_in_unsafe_fn)]
#[path = "../../setup-stream-kernel/src/arithmetic.rs"]
mod arithmetic;
mod engine;
mod profile;
#[path = "stream-bridge.rs"]
#[cfg(feature = "bridge")]
mod stream_bridge;
mod statement {
    pub use setup_stream_kernel::{
        SetupStatementOutput as StatementOutput, SetupStatementStream as StatementStream,
    };
}
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal, Verifier};
