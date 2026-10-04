//! Outer seed-sharing operands for the shared test-support prover.
use crate::{
    layout::Layout,
    operator,
    statement::{Statement, encoded_bytes},
    verification::ROLE,
};
use supported_profile::relation::Relation;
pub use word_proof::staged::{DONE_PHASE, Error, OUTPUT_BYTES, OUTPUT_PHASE};
use word_proof::{affine::Operator, field::Element, staged::AffineStatement};

pub const POSITIVE_PROOF_RANDOMNESS_SEED: u64 = 0x2165_5c07_319b_8481;
pub type Prover = word_proof::staged::Prover<Statement>;

impl AffineStatement for Statement {
    const ROLE: &'static [u8] = ROLE;
    fn relation(&self) -> Relation {
        Layout::new(encoded_bytes()).relation
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        Statement::encode(self).map_err(|_| Error::Context)
    }
    fn operator(&self, alpha: Element) -> Result<Operator, Error> {
        operator::build(self, alpha).map_err(|_| Error::Context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mismatched_statement_or_relation_never_starts_the_replay() {
        let (mut statement, witness) = crate::fixture::create();
        statement.scope.author = 0;
        assert!(matches!(
            Prover::new(statement, witness, POSITIVE_PROOF_RANDOMNESS_SEED, false),
            Err(Error::Context)
        ));
        assert_eq!(word_proof::random::REPLAYED.with(|state| state.get()), None);

        let (statement, mut witness) = crate::fixture::create();
        witness.relation.parameters[0] += 1;
        assert!(matches!(
            Prover::new(statement, witness, POSITIVE_PROOF_RANDOMNESS_SEED, false),
            Err(Error::Context)
        ));
        assert_eq!(word_proof::random::REPLAYED.with(|state| state.get()), None);

        let (mut statement, witness) = crate::fixture::create();
        statement.common[0] = crate::modulus();
        assert!(matches!(
            Prover::new(statement, witness, POSITIVE_PROOF_RANDOMNESS_SEED, false),
            Err(Error::Context)
        ));
        assert_eq!(word_proof::random::REPLAYED.with(|state| state.get()), None);
    }
    #[test]
    fn one_replay_lifetime_survives_refused_control_calls() {
        let (statement, witness) = crate::fixture::create();
        let mut prover =
            Prover::new(statement, witness, POSITIVE_PROOF_RANDOMNESS_SEED, false).unwrap();
        assert_eq!(prover.phase(), 1);
        assert_eq!(prover.next_output(), Err(Error::Stage));
        assert_eq!(prover.acknowledge_output(), Err(Error::Stage));
        assert_eq!(prover.phase(), 1);
        assert!(prover.output().is_empty());
        assert_eq!(
            word_proof::random::REPLAYED.with(|state| state.get()),
            Some(POSITIVE_PROOF_RANDOMNESS_SEED)
        );
        let (statement, witness) = crate::fixture::create();
        assert!(matches!(
            Prover::new(statement, witness, 17, false),
            Err(Error::Stage)
        ));
        assert_eq!(
            word_proof::random::REPLAYED.with(|state| state.get()),
            Some(POSITIVE_PROOF_RANDOMNESS_SEED)
        );
        drop(prover);
        assert_eq!(word_proof::random::REPLAYED.with(|state| state.get()), None);
    }
}
