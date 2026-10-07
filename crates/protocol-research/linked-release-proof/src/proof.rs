use crate::{PreparedRelease, parameters::*, statement::PublicStatement};
use word_proof::{one_shot::OneShotProof, oracles::Witness};

/// Proves a prepared release, returning its public statement and proof.
pub fn prove(role: &[u8], mut prepared: PreparedRelease) -> (PublicStatement, OneShotProof) {
    let statement = prepared.statement;
    let witness = Witness::from_columns(
        &release_relation(statement.profile),
        statement.digest(),
        std::mem::take(&mut *prepared.columns),
    )
    .unwrap();
    let proof = OneShotProof::create(
        role,
        witness,
        &statement.header,
        &statement.polynomials,
        |alpha| statement.operator(alpha).unwrap(),
        false,
    );
    (statement, proof)
}

#[cfg(test)]
#[path = "proof-tests.rs"]
mod tests;
