use crate::statement::PublicStatement;
use word_proof::{one_shot::OneShotProof, oracles::Witness};

/// Proves the ballot statement with a witness of the statement profile's
/// ballot relation.
pub fn prove(
    role: &[u8],
    public: &PublicStatement,
    witness: Witness,
    adversarial_affine: bool,
) -> OneShotProof {
    OneShotProof::create(
        role,
        witness,
        &public.header,
        &public.polynomials,
        |alpha| public.operator(alpha).unwrap(),
        adversarial_affine,
    )
}

#[cfg(test)]
#[path = "proof-tests.rs"]
mod tests;
