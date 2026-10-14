#![deny(unsafe_op_in_unsafe_fn)]
pub mod engine;
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};
use statement_stream::{
    SetupStatementStream, StatementOutput,
    affine::{HeaderThenPolynomials, OperatorBuilder},
};
use supported_profile::{Profile, relation::setup_relation};

impl engine::Statement for SetupStatementStream {
    fn push(&mut self, bytes: &[u8]) -> bool {
        SetupStatementStream::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<StatementOutput> {
        SetupStatementStream::finish(self).ok()
    }
}
impl<B: OperatorBuilder> engine::Statement for HeaderThenPolynomials<B> {
    fn push(&mut self, bytes: &[u8]) -> bool {
        HeaderThenPolynomials::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<StatementOutput> {
        HeaderThenPolynomials::finish(self).ok()
    }
}

pub type SetupContributionVerifier = engine::Verifier<SetupStatementStream>;
/// Verifies a complete setup contribution proof of one profile.
pub fn setup_contribution_verifier(
    profile: Profile,
    role: &[u8],
    proof_header: &[u8],
) -> Result<SetupContributionVerifier, Refusal> {
    SetupContributionVerifier::open(
        setup_relation(profile),
        role,
        proof_header,
        |statement, alpha, queries| {
            SetupStatementStream::new(profile, statement, alpha, queries).ok()
        },
    )
}

#[cfg(test)]
#[path = "lib-tests.rs"]
mod tests;
