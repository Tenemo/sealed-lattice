use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(RELATION_PROOF_BYTES_HASH_DOMAIN, &[proof_bytes])
}

// Binds the operative identity of the internal direct-ballot validity relation proof: statement
// hash domain, challenge size and domain, proof-bytes domain, ring degree, and data prime count.
pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_proof_parameters_hash()
-> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": "BallotValidityProofParameters",
        "statementHashDomain": RELATION_STATEMENT_HASH_DOMAIN,
        "challengeBits": RELATION_PROOF_CHALLENGE_BITS,
        "challengeDomain": "sealed-lattice/direct-encrypted-ballot/relation-challenge",
        "proofBytesDomain": RELATION_PROOF_BYTES_HASH_DOMAIN,
        "sourceRingDegree": POLYNOMIAL_DEGREE,
        "dataPrimeCount": DATA_PRIMES.len(),
    }))
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_response_bytes() -> usize {
    (RELATION_WITNESS_POLYNOMIALS * POLYNOMIAL_DEGREE
        + direct_ballot_relation_response_scalar_count())
        * RELATION_RESPONSE_COEFFICIENT_BYTES
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_commitment_bytes() -> usize {
    (DATA_PRIMES.len() * 2 * POLYNOMIAL_DEGREE
        + direct_ballot_score_linear_commitment_scalar_count())
        * size_of::<u64>()
        + direct_ballot_support_commitment_bytes()
}

pub(in crate::bgv::direct_ballots) fn direct_ballot_relation_response_scalar_count() -> usize {
    OPTION_COUNT + OPTION_COUNT * SCORE_BUCKET_COUNT
}

pub(super) fn direct_ballot_score_linear_commitment_scalar_count() -> usize {
    OPTION_COUNT * 2
}

pub(super) fn direct_ballot_support_commitment_bytes() -> usize {
    direct_ballot_support_commitment_scalar_count() * size_of::<u64>()
}

pub(super) fn direct_ballot_support_commitment_scalar_count() -> usize {
    OPTION_COUNT * SCORE_BUCKET_COUNT * ONE_HOT_SUPPORT_EXPANSION_COEFFICIENTS
        + POLYNOMIAL_DEGREE * RANDOMIZER_SUPPORT_EXPANSION_COEFFICIENTS
        + 2 * POLYNOMIAL_DEGREE * ERROR_SUPPORT_EXPANSION_COEFFICIENTS
}
