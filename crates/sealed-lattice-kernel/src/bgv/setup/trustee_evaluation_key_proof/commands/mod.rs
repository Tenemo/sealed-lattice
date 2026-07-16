#[cfg(test)]
use super::relation::{TrusteeEvaluationKeyStatement, TrusteeEvaluationKeyWitness};
#[cfg(test)]
use crate::bgv::setup::ProofByteSource;
#[cfg(test)]
use crate::bgv::setup::limb_group_key_switch_atom::family_backend::schedule as atom_schedule;
#[cfg(test)]
use crate::encoding::CanonicalResult;

pub(in crate::bgv::setup) struct VssPublicCommandCommitmentExpectation<'a> {
    pub(in crate::bgv::setup) field_name: String,
    pub(in crate::bgv::setup) root: &'a str,
}

// Trustee evaluation-key statements use the key-switch atom backend. The
// common proof suite owns public-key, same-secret, VSS-linkage, and target
// decryption relations.
#[cfg(test)]
pub(in crate::bgv::setup) fn prove_trustee_evaluation_key_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    witness: &TrusteeEvaluationKeyWitness,
    proof_randomness_seed_hex: &str,
) -> CanonicalResult<Vec<u8>> {
    atom_schedule::prove_key_bearing_trustee_evaluation_keys(
        statement,
        witness,
        proof_randomness_seed_hex,
    )
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verify_trustee_evaluation_key_proof_bytes(
    statement: &TrusteeEvaluationKeyStatement,
    proof_bytes: &(impl ProofByteSource + ?Sized),
) -> CanonicalResult<()> {
    atom_schedule::verify_key_bearing_trustee_evaluation_keys(statement, proof_bytes)
}

mod vss_commitment_parsing;

pub(in crate::bgv::setup) use vss_commitment_parsing::vss_share_linkage_commitment_from_value;
