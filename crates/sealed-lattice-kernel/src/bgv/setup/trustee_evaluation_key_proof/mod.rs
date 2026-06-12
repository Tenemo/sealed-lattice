// Trustee evaluation-key proof: one masked succinct polynomial-IOP argument
// per trustee covering the whole frozen evaluation-key schedule. For every
// listed key (relinearization round one, round two, or a Galois rotation),
// every digit j, and every RNS limb l of that key's level,
//
//   b_{j,l} + a_{j,l} * s - p * e_j - [l == j] * source_j = 0 in R_{q_l}
//
// with the diagonal source s, s (*) round-one aggregate, or phi_g(s) by kind.
// The shared witness is committed in evaluation form per limb field, batched
// across digits and keys by random challenges, and bound across limb fields by
// bounded random integer combinations of the small witness, published behind
// shared smudging masks so the masked claims stay comparable as centered
// integers without revealing the clear sums. The same-secret linkage opens the
// accepted BDLOP constant commitments natively over the commitment-modulus
// fields, so the proven key-relation secret is the committed trustee secret.
//
// Claim boundary: this argument is the evaluation-key proof path of the
// accepted setup package; the package verifier rebuilds every statement from
// the transported share records, the recomputed round-one public aggregates,
// and the accepted same-secret commitments. The accounting object in this
// module still carries open theorem items — the proven FRI bound, the
// cross-limb consistency lemma, the simulator argument, the smudging budget,
// and the multi-round QROM accounting are documented budgets with explicit
// not-accepted status — so packages verified through this path remain
// ClaimClosureMissing until those rows close.
//
// Argument shape per limb field F_{q_l} (one trace commitment and one batched
// FRI instance per limb, shared by every listed key):
// - each logical length-N vector (secret, per-key errors, error squares, and
//   claim-mask digits) is split into TRACE_SPLIT physical columns over the
//   trace domain of size N / TRACE_SPLIT, masked with a fresh random multiple
//   of Z_H, and committed in a salted Merkle tree over the DOMAIN_BLOWUP coset
//   low-degree extension;
// - vanishing row checks (ternary secret, centered-binomial error support,
//   square well-formedness, binary mask digits) batched into a split quotient;
// - one univariate sumcheck batching every key's digit-batched linear
//   key-switch check and the masked cross-limb consistency claims;
// - DEEP out-of-domain points binding the identities to the committed columns
//   through quotients in the per-limb batched FRI instance.

mod accounting;
mod commands;
mod evaluation_domain;
mod fiat_shamir_transcript;
mod low_degree_proof;
mod merkle_commitment;
mod proof_codec;
mod prover;
mod relation;
mod verifier;

pub(crate) use commands::{
    generate_trustee_evaluation_key_proof_from_request,
    verify_trustee_evaluation_key_proof_from_request,
};

pub(in crate::bgv::setup) use accounting::{
    succinct_evaluation_key_proof_accounting_hash, succinct_evaluation_key_proof_accounting_value,
};
pub(in crate::bgv::setup) use proof_codec::decode_trustee_evaluation_key_proof;
#[cfg(test)]
pub(in crate::bgv::setup) use proof_codec::encode_trustee_evaluation_key_proof;
#[cfg(test)]
pub(in crate::bgv::setup) use prover::prove_evaluation_key_share;
pub(in crate::bgv::setup) use relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, SameSecretLinkageStatement,
    TrusteeEvaluationKeyContext, TrusteeEvaluationKeyStatement,
};
#[cfg(test)]
pub(in crate::bgv::setup) use relation::TrusteeEvaluationKeyWitness;
pub(in crate::bgv::setup) use verifier::verify_evaluation_key_share;

#[cfg(test)]
mod tests;

use crate::{
    bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast, sub_mod_fast},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::hash512_hex,
};

// Canonical hash of transported trustee evaluation-key proof bytes, bound into
// the package proof records and the chunked proof transport reference.
pub(in crate::bgv::setup) fn trustee_evaluation_key_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(
        "sealed-lattice/setup/trustee-evaluation-key/proof-bytes-v1",
        &[proof_bytes],
    )
}

pub(crate) const TRUSTEE_EVALUATION_KEY_PROOF_FAMILY: &str = "trustee-evaluation-key";
// The model status keeps the open theorem items visible on every record: the
// argument is verified, the accounting rows are not yet accepted.
pub(crate) const TRUSTEE_EVALUATION_KEY_PROOF_MODEL_STATUS: &str =
    "succinct-trustee-evaluation-key-argument-accounting-pending";
pub(crate) const TRUSTEE_EVALUATION_KEY_PROOF_VERIFICATION_STATUS: &str =
    "succinct-trustee-evaluation-key-argument-verified-with-open-proof-accounting";

// Each logical length-N witness vector is split into TRACE_SPLIT physical
// columns over a trace domain of size N / TRACE_SPLIT. The split frees domain
// headroom under the guaranteed 2-adicity of the profile primes (2^16 divides
// q - 1): the extension coset is DOMAIN_BLOWUP times the trace, and committed
// columns claim degree below COMMITMENT_BOUND_FACTOR times the trace, so the
// batched FRI still runs at rate 1/2 while masked columns of degree
// trace + COLUMN_MASK_DEGREE fit under the bound without splitting.
pub(super) const TRACE_SPLIT: usize = 2;
pub(super) const DOMAIN_BLOWUP: usize = 4;
pub(super) const COMMITMENT_BOUND_FACTOR: usize = 2;
// Random Z_H-multiple mask degree per committed column. Every committed
// column is opened at most 2 * query count + deep points times, so 256 random
// mask coefficients make the revealed evaluations uniform at full size. The
// cap trace / 4 keeps the cubic row-check composition inside the blowup.
pub(super) fn column_mask_degree(trace_size: usize) -> usize {
    256.min(trace_size / 4)
}
// Out-of-domain evaluation points per limb; identity soundness is about
// (composition degree / field size) per point, around 2^-31 at full size.
pub(super) const DEEP_POINT_COUNT: usize = 3;
// Independent power-challenge repetitions of the linear-relation sumcheck;
// each contributes about (trace size / field size), around 2^-32.
pub(super) const LINCHECK_REPETITIONS: usize = 3;
// Cross-limb witness-consistency repetitions and the bit width of the public
// integer coefficients. Narrow eight-bit coefficients keep the clear sums
// small (at most 2 * N * 255, about 2^24) so the forty-five-bit smudging
// masks dominate them; twenty repetitions put the per-difference collision
// bound at 2^-160 before union and Fiat-Shamir losses, the pre-union margin
// the accounting certificate requires.
pub(super) const CONSISTENCY_REPETITIONS: usize = 20;
pub(super) const CONSISTENCY_COEFFICIENT_BITS: u32 = 8;
// Each consistency claim is published as claim + mask, with the mask a
// forty-five-bit value committed digit-wise in binary mask columns. The mask
// bound plus the clear-sum bound stays below half the smallest profile prime,
// so centered representatives remain field-independent integers.
pub(super) const CLAIM_MASK_DIGIT_COUNT: usize = 45;
// FRI query count at rate 1/2 under the conjectured per-query soundness of
// one half: about 2^-100 for one hundred queries. No grinding is applied.
pub(super) const LOW_DEGREE_QUERY_COUNT: usize = 100;
// The FRI recursion stops once the claimed degree bound reaches this size and
// the final polynomial is sent in coefficient form.
pub(super) const LOW_DEGREE_FINAL_COEFFICIENT_COUNT: usize = 8;
// Smallest supported trace size keeps every domain a usable power of two.
pub(super) const MINIMUM_TRACE_SIZE: usize = 64;

fn invalid_succinct_setup_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

// Centered representative of a residue as a signed integer.
pub(super) fn centered_residue_i128(value: u64, modulus: u64) -> i128 {
    if value > modulus / 2 {
        i128::from(value) - i128::from(modulus)
    } else {
        i128::from(value)
    }
}

// Residue of a signed integer in [0, modulus).
pub(super) fn signed_value_residue(value: i64, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let reduced = (i128::from(value) % modulus_i128 + modulus_i128) % modulus_i128;
    u64::try_from(reduced).expect("reduced signed residue fits u64")
}
