#![deny(unsafe_op_in_unsafe_fn)]
mod convolution;
pub mod proof;
pub mod statement;
mod witness;
use statement::StatementStream;
use supported_profile::{Profile, relation::release_relation};
pub use witness::{PreparedRelease, ReleaseInputError, ReleaseInputs, derive_bound};
use word_verifier::engine;
pub use word_verifier::engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};

pub type Verifier = engine::Verifier<StatementStream>;
/// Verifies one profile's release proof against its expected statement.
pub fn verifier(
    profile: Profile,
    role: &[u8],
    expected_statement: [u8; 64],
    proof_header: &[u8],
) -> Result<Verifier, Refusal> {
    Verifier::open(
        release_relation(profile),
        role,
        expected_statement,
        proof_header,
        |alpha, queries| StatementStream::new(profile, expected_statement, alpha, queries).ok(),
    )
}
