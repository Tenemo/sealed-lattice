#![deny(unsafe_op_in_unsafe_fn)]
pub mod engine;
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};
use setup_stream_kernel::{SetupStatementOutput, SetupStatementStream};
use supported_profile::{Profile, relation::setup_relation};

impl engine::Statement for SetupStatementStream {
    fn push(&mut self, bytes: &[u8]) -> bool {
        SetupStatementStream::push(self, bytes).is_ok()
    }
    fn finish(self) -> Option<SetupStatementOutput> {
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
mod tests {
    use supported_profile::{
        Profile,
        relation::{ballot_relation, release_relation, setup_relation},
    };

    // The verifier's own context parameters equal the prover's for every
    // relation of every profile.
    #[test]
    fn verifier_and_prover_bind_the_same_relation_parameters() {
        let mut relations = Vec::new();
        for profile in Profile::all() {
            relations.extend([
                setup_relation(profile),
                ballot_relation(profile),
                release_relation(profile),
            ]);
        }
        for relation in relations {
            assert_eq!(
                super::engine::context_parameters(&relation),
                word_proof::transcript::parameters(&relation)
            );
        }
    }
}
