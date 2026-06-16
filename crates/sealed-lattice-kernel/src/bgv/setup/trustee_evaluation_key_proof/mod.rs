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
// module is closed: every post-commitment challenge is drawn from the
// degree-four challenge extension of the limb field, the masked claims are
// integer-bound across limb fields by a two-prime lift, and every theorem row
// carries its closure argument with one explicitly named conjecture (the CS25
// entropy-capacity FRI proximity-gap bound; see accounting.rs for the 2026
// Option B re-basing off the disproved up-to-capacity conjecture), classical
// Fiat-Shamir accounting, reference-only QROM rows, and a bounded-leakage
// smudging scope rather than 128-bit zero-knowledge.
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
mod extension_field;
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
    succinct_private_vss_share_accounting_hash, succinct_private_vss_share_accounting_value,
    succinct_public_key_share_accounting_hash, succinct_public_key_share_accounting_value,
    succinct_same_secret_linkage_anchor_accounting_hash,
    succinct_same_secret_linkage_anchor_accounting_value,
};
pub(in crate::bgv::setup) use proof_codec::decode_trustee_evaluation_key_proof;
pub(in crate::bgv::setup) use proof_codec::encode_trustee_evaluation_key_proof;
pub(in crate::bgv::setup) use prover::prove_evaluation_key_share;
pub(in crate::bgv::setup) use relation::TrusteeEvaluationKeyWitness;
pub(in crate::bgv::setup) use relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
    PrivateVssShareStatement, SameSecretLinkageStatement, SuccinctSetupProofContext,
    TrusteeEvaluationKeyStatement,
};
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
pub(crate) const SAME_SECRET_LINKAGE_ANCHOR_PROOF_FAMILY: &str = "same-secret-linkage-anchor";
pub(crate) const PUBLIC_KEY_SHARE_PROOF_FAMILY: &str = "public-key-share";
pub(crate) const PRIVATE_VSS_SHARE_PROOF_FAMILY: &str = "vss-opening-carry";
// Canonical hash of transported same-secret linkage anchor proof bytes.
pub(in crate::bgv::setup) fn same_secret_anchor_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(
        "sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1",
        &[proof_bytes],
    )
}

// Canonical hash of transported public-key share succinct proof bytes.
pub(in crate::bgv::setup) fn public_key_share_succinct_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(
        "sealed-lattice/setup/public-key-share/succinct-proof-bytes-v1",
        &[proof_bytes],
    )
}

// Canonical hash of transported private VSS succinct proof bytes.
pub(in crate::bgv::setup) fn private_vss_share_succinct_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(
        "sealed-lattice/setup/private-vss-share/succinct-proof-bytes-v1",
        &[proof_bytes],
    )
}

// Each logical length-N witness vector is split into TRACE_SPLIT physical
// columns over a trace domain of size N / TRACE_SPLIT. The split frees domain
// headroom under the guaranteed 2-adicity of the profile primes (2^16 divides
// q - 1): the extension coset is DOMAIN_BLOWUP times the trace, and committed
// columns claim degree below COMMITMENT_BOUND_FACTOR times the trace, so the
// batched FRI still runs at rate 1/2 while masked columns of degree
// trace + COLUMN_MASK_DEGREE fit under the bound without splitting.
// TRACE_SPLIT packs each logical length-N witness as two half-columns over a
// half-size domain because only 2^16 divides p-1 (two-adicity headroom); a
// full-N coset would not fit at the rate-one-half blowup.
pub(super) const TRACE_SPLIT: usize = 2;
pub(super) const DOMAIN_BLOWUP: usize = 4;
pub(super) const COMMITMENT_BOUND_FACTOR: usize = 2;
// Random Z_H-multiple mask degree per committed column. Every committed
// column is opened at most 2 * query count + deep points times (338 at the
// selected parameters), so 512 random mask coefficients cover the opened
// evaluations with margin at full size. The cap trace / 4 keeps the cubic
// row-check composition inside the blowup; development ring sizes below the
// full profile fall under the cap and are not zero-knowledge evidence.
pub(super) fn column_mask_degree(trace_size: usize) -> usize {
    512.min(trace_size / 4)
}
// Out-of-domain evaluation points per limb; identity soundness per point is
// (composition degree / challenge field size), around 2^-171 at full size
// with degree-four extension challenges.
pub(super) const DEEP_POINT_COUNT: usize = 2;
// Independent power-challenge repetitions of the linear-relation sumcheck;
// each contributes about (trace size / challenge field size), around 2^-174.
pub(super) const LINCHECK_REPETITIONS: usize = 2;
// Cross-limb witness-consistency repetitions and the bit width of the public
// integer coefficients. Narrow eight-bit coefficients keep the clear sums
// small (at most 2 * N * 255, about 2^24) so the ninety-two-bit smudging
// masks dominate them only as a bounded-leakage row; twenty repetitions put
// the per-difference collision bound at 2^-160 before union and Fiat-Shamir
// losses, the pre-union margin the accounting certificate requires.
pub(super) const CONSISTENCY_REPETITIONS: usize = 20;
pub(super) const CONSISTENCY_COEFFICIENT_BITS: u32 = 8;
// Each consistency claim is one shared integer (clear bounded combination
// plus a ninety-two-bit mask committed digit-wise in binary mask columns)
// published as its residue in every limb field. The product of the two
// smallest profile primes exceeds twice the claim bound, so the verifier's
// centered two-prime lift is unique and per-claim leakage is the clear bound
// over the mask bound, about 2^-68. This is not a 128-bit zero-knowledge row.
pub(super) const CLAIM_MASK_DIGIT_COUNT: usize = 92;
// FRI query count at rate 1/2. CHANGE (2026, Option B): the per-query
// soundness is no longer the disproved one-bit (1 - rho) up-to-capacity bound
// but the CS25 entropy-capacity bound (about 0.938 bit per query for the prime
// base field), so 168 queries record about 156 bits before the union allowance
// and about 140 after it, still clearing 128. The proven BCIKS20 Johnson
// fallback (half a bit per query) would need roughly 288 queries. See
// accounting.rs for the full re-basing. No grinding is applied.
pub(super) const LOW_DEGREE_QUERY_COUNT: usize = 168;
// The FRI recursion stops once the claimed degree bound reaches this size and
// the final polynomial is sent in coefficient form.
pub(super) const LOW_DEGREE_FINAL_COEFFICIENT_COUNT: usize = 8;
// Smallest supported trace size keeps every domain a usable power of two.
pub(super) const MINIMUM_TRACE_SIZE: usize = 64;

fn invalid_succinct_setup_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// Residue of a signed integer in [0, modulus).
pub(super) fn signed_value_residue(value: i64, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let reduced = (i128::from(value) % modulus_i128 + modulus_i128) % modulus_i128;
    u64::try_from(reduced).expect("reduced signed residue fits u64")
}
