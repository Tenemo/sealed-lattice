#![deny(unsafe_op_in_unsafe_fn)]
pub mod engine;
pub use engine::public_evaluation;
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};
use statement_stream::{
    StatementOutput,
    affine::{HeaderThenPolynomials, OperatorBuilder},
};

impl<B: OperatorBuilder> engine::Statement for HeaderThenPolynomials<B> {
    fn push(&mut self, bytes: &[u8]) -> bool {
        HeaderThenPolynomials::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<StatementOutput> {
        HeaderThenPolynomials::finish(self).ok()
    }
}

#[cfg(test)]
#[path = "lib-tests.rs"]
mod tests;
