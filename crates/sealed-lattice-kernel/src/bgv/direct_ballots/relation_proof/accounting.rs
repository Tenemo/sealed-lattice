use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(
        DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
        &[proof_bytes],
    )
}

// Binds the operative shape of the internal direct-ballot validity relation proof: statement
// hash domain, encoding, challenge size and domain, proof-bytes domain, relation shape, ring
// degree, and data prime count.
//
// Scope, kept in prose rather than a bound field: this is an internal relation-shape proof.
// Its claim soundness and support zero-knowledge are not established. The weakest checked
// subrelation runs modulo the about 16-bit plaintext modulus 65537, so a single transcript
// yields only about 16 soundness bits against the 192-bit nominal challenge. See the README
// safety boundaries for the full scope statement.
pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_parameters_hash()
-> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "BallotValidityProofParameters",
        "statementHashDomain": DIRECT_BALLOT_RELATION_STATEMENT_HASH_DOMAIN,
        "proofEncoding": "binary relation transcript",
        "challengeBits": DIRECT_BALLOT_RELATION_PROOF_CHALLENGE_BITS,
        "challengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge-v1",
        "proofBytesDomain": DIRECT_BALLOT_RELATION_PROOF_BYTES_HASH_DOMAIN,
        "relation": "BGV all-limb encryption equations, score encoding, one-hot constraints, randomizer support, and error support",
        "sourceRingDegree": POLYNOMIAL_DEGREE,
        "dataPrimeCount": DATA_PRIMES.len(),
    }))
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_response_bytes() -> usize {
    (DIRECT_BALLOT_RELATION_WITNESS_POLYNOMIALS * POLYNOMIAL_DEGREE
        + direct_ballot_relation_response_scalar_count())
        * DIRECT_BALLOT_RELATION_RESPONSE_COEFFICIENT_BYTES
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_commitment_bytes() -> usize {
    (DATA_PRIMES.len() * 2 * POLYNOMIAL_DEGREE
        + direct_ballot_score_linear_commitment_scalar_count())
        * size_of::<u64>()
        + direct_ballot_support_commitment_bytes()
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_response_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT + DIRECT_BALLOT_OPTION_COUNT * DIRECT_BALLOT_SCORE_BUCKET_COUNT
}

pub(super) fn direct_ballot_score_linear_commitment_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT * 2
}

pub(super) fn direct_ballot_support_commitment_bytes() -> usize {
    direct_ballot_support_commitment_scalar_count() * size_of::<u64>()
}

pub(super) fn direct_ballot_support_commitment_scalar_count() -> usize {
    DIRECT_BALLOT_OPTION_COUNT
        * DIRECT_BALLOT_SCORE_BUCKET_COUNT
        * DIRECT_BALLOT_ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS
        + POLYNOMIAL_DEGREE * DIRECT_BALLOT_RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS
        + 2 * POLYNOMIAL_DEGREE * DIRECT_BALLOT_ERROR_SUPPORT_EXPANSION_COEFFICIENTS
}
