#![deny(unsafe_op_in_unsafe_fn)]
pub mod proof;
pub mod statement;
mod witness;
use statement::StatementStream;
use supported_profile::{Profile, relation::release_relation};
pub use witness::{PreparedRelease, ReleaseInputRefusal, ReleaseInputs, prepare_release};
use word_verifier::engine;
pub use word_verifier::engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};

pub type Verifier = engine::Verifier<StatementStream>;
/// Verifies one profile's release proof.
pub fn verifier(profile: Profile, role: &[u8], proof_header: &[u8]) -> Result<Verifier, Refusal> {
    Verifier::open(
        release_relation(profile),
        role,
        proof_header,
        |statement, alpha, queries| StatementStream::new(profile, statement, alpha, queries).ok(),
    )
}
