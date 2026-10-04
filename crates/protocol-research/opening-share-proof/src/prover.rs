//! Relation adapter for the shared native/scalar staged proof controller.
use crate::{
    layout::Layout,
    operator,
    statement::{Statement, encoded_bytes},
};
pub use word_proof::staged::{DONE_PHASE, Error, OUTPUT_BYTES, OUTPUT_PHASE};
use word_proof::{affine::Operator, field::Element, staged::AffineStatement};
pub const POSITIVE_PROOF_RANDOMNESS_SEED: u64 = 0x54d6_1179_245a_68b3;
pub type Prover = word_proof::staged::Prover<Statement>;

impl AffineStatement for Statement {
    const ROLE: &'static [u8] = crate::ROLE;
    fn relation(&self) -> supported_profile::relation::Relation {
        Layout::new(encoded_bytes()).relation
    }
    fn encode(&self) -> Result<Vec<u8>, Error> {
        Statement::encode(self).map_err(|_| Error::Context)
    }
    fn operator(&self, alpha: Element) -> Result<Operator, Error> {
        operator::build(self, alpha).map_err(|_| Error::Context)
    }
}
