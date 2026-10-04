//! Explicit native proof experiment. The producer can exercise the common
//! engine's hostile affine path; the owning verifier is never weakened.
use crate::{
    layout::Layout,
    operator,
    statement::{Statement, encoded_bytes},
};
use std::io::Write;
use word_proof::{
    combination, field, fri,
    linear_oracle::LinearOracle,
    oracles::{FirstOracle, SecondOracle, Witness},
    parameters::{DOMAIN, SYSTEMATIC},
    transcript::{self, Transcript},
};

pub use crate::verification::{ROLE, VerificationError, verify};

struct Replay;
impl Drop for Replay {
    fn drop(&mut self) {
        word_proof::random::REPLAYED.with(|state| state.set(None));
    }
}

/// Writes one full common-engine proof directly to its artifact. The replay
/// seed supplies proof randomness only, independently of the opening seed
/// and every fixed sharing/encryption input of this synthetic experiment.
pub fn write(
    statement: &Statement,
    witness: Witness,
    replay_seed: u64,
    false_affine: bool,
    output: &mut impl Write,
) -> std::io::Result<()> {
    let relation = &witness.relation;
    assert_eq!(relation, &Layout::new(encoded_bytes()).relation);
    assert_eq!(witness.statement, statement.digest().unwrap());
    word_proof::random::REPLAYED.with(|state| state.set(Some(replay_seed)));
    let _replay = Replay;
    let bytes = statement.encode().unwrap();
    let mut context_hash = transcript::context_hasher(relation, ROLE);
    context_hash.update(&bytes);
    let context = context_hash.finalize();
    let mut transcript = Transcript::new(ROLE, context, relation.message_bytes());
    transcript.next();
    let first = FirstOracle::create(ROLE, &witness, false);
    transcript.respond(&[&first.tree.root()]);
    transcript.next();
    let beta = transcript::challenge(&transcript.message, 0, true);
    let inverses = field::batch_inverse(
        &(0..SYSTEMATIC)
            .map(|value| field::subtract(beta, [value as u128, 0, 0]))
            .collect::<Vec<_>>(),
    );
    let second = SecondOracle::create(ROLE, &witness, &inverses);
    transcript.respond(&[&second.tree.root(), &field::encode(second.mask_sum)]);
    transcript.next();
    let alpha = transcript::challenge(&transcript.message, 0, false);
    let mask = transcript::challenge(&transcript.message, 1, false);
    let linear = LinearOracle::create(
        ROLE,
        &witness,
        &first,
        &second,
        operator::build(statement, alpha).unwrap(),
        mask,
        false_affine,
    );
    transcript.respond(&[&linear.tree.root()]);
    transcript.next();
    let coefficients = combination::polynomial(
        &witness,
        &first,
        &second,
        &linear,
        beta,
        &inverses,
        &transcript.message,
    );
    let folding = fri::Fri::create(ROLE, relation.oracles(), coefficients, &mut transcript);
    output.write_all(relation.proof_magic)?;
    output.write_all(&witness.statement)?;
    output.write_all(&context)?;
    for root in [first.tree.root(), second.tree.root(), linear.tree.root()] {
        output.write_all(&root)?;
    }
    output.write_all(&field::encode(second.mask_sum))?;
    for salt in &transcript.salts {
        output.write_all(salt)?;
    }
    for layer in &folding.layers {
        output.write_all(&layer.tree.root())?;
    }
    output.write_all(&field::encode(folding.terminal))?;
    let indices = fri::requested(&folding.queries, DOMAIN);
    first.tree.write_multiproof(
        &indices,
        |leaves| first.opened_rows(&witness, leaves),
        output,
    );
    second.tree.write_multiproof(
        &indices,
        |leaves| second.opened_rows(&witness, &inverses, leaves),
        output,
    );
    linear
        .tree
        .write_multiproof(&indices, |leaves| linear.opened_rows(leaves), output);
    for layer in &folding.layers {
        let indices = fri::requested(&folding.queries, layer.tree.length);
        layer
            .tree
            .write_multiproof(&indices, |leaves| layer.rows(leaves), output);
    }
    output.flush()
}
