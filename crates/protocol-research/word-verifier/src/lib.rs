#![deny(unsafe_op_in_unsafe_fn)]
#[path = "../../setup-stream-kernel/src/arithmetic.rs"]
mod arithmetic;
mod engine;
mod statement {
    pub use setup_stream_kernel::SetupStatementOutput as StatementOutput;
}
pub use engine::{CHUNK_LIMIT, HEADER_LENGTH, Refusal};
use setup_stream_kernel::SetupStatementStream;
use statement::StatementOutput;
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
impl Verifier {
    /// Verifies a complete setup contribution proof of one profile.
    pub fn new(
        profile: Profile,
        role: &[u8],
        expected_statement: [u8; 64],
        proof_header: &[u8],
    ) -> Result<Self, Refusal> {
        Self::open(
            setup_relation(profile),
            role,
            expected_statement,
            proof_header,
            |alpha, queries| {
                SetupStatementStream::new(profile, expected_statement, alpha, queries).ok()
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use supported_profile::{
        Profile,
        relation::{ballot_relation, registration_relation, release_relation, setup_relation},
    };

    // The verifier's own context parameters equal the prover's for every
    // relation of every profile.
    #[test]
    fn verifier_and_prover_bind_the_same_relation_parameters() {
        let mut relations = vec![registration_relation()];
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
