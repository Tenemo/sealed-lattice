//! The native writer drains the same staged prover as the scalar fixture.
use crate::{
    prover::{DONE_PHASE, OUTPUT_PHASE, Prover},
    statement::Statement,
};
use std::io::Write;
use word_proof::oracles::Witness;

pub use crate::verification::{ROLE, VerificationError, verify};

pub fn write(
    statement: &Statement,
    witness: Witness,
    replay_seed: u64,
    false_affine: bool,
    output: &mut impl Write,
) -> std::io::Result<()> {
    let failure = |error| std::io::Error::other(format!("Prover refused: {error:?}"));
    let mut prover =
        Prover::new(statement.clone(), witness, replay_seed, false_affine).map_err(failure)?;
    loop {
        match prover.phase() {
            DONE_PHASE => return output.flush(),
            OUTPUT_PHASE => {
                prover.next_output().map_err(failure)?;
                if !prover.output().is_empty() {
                    output.write_all(prover.output())?;
                    prover.acknowledge_output().map_err(failure)?;
                }
            }
            _ => prover.step().map_err(failure)?,
        }
    }
}
