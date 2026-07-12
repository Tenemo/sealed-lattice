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
// Trust boundary: this argument is an experimental evaluation-key proof path.
// The package verifier rebuilds every statement from transported share records,
// recomputed round-one public aggregates, and same-secret commitments before
// checking the implemented polynomial identities. The current proof does not
// have an accepted end-to-end extraction, QROM, or zero-knowledge theorem at the
// required profile, so callers must not treat successful verification as
// certified foundation evidence.
//
// Argument shape per limb field F_{q_l} (one trace commitment and one batched
// FRI instance per limb, shared by every listed key):
// - each logical length-N vector (secret, per-key errors, error squares, and
//   claim-mask digits) is split into TRACE_SPLIT physical columns over the
//   trace domain of size N / TRACE_SPLIT, masked with a fresh random multiple
//   of Z_H, and committed in a salted Merkle tree over the DOMAIN_BLOWUP coset
//   low-degree extension;
// - vanishing row checks (ternary secret, centered-binomial error support,
//   square well-formedness, base-3 mask digits) batched into a split quotient;
// - one univariate sumcheck batching every key's digit-batched linear
//   key-switch check and the masked cross-limb consistency claims;
// - DEEP out-of-domain points binding the identities to the committed columns
//   through quotients in the per-limb batched FRI instance.

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

#[cfg(test)]
pub(crate) use commands::describe_target_decryption_share_proof_layout_from_request;
pub(crate) use commands::describe_trustee_evaluation_key_statement_from_request;
pub(crate) use commands::generate_target_decryption_share_proof_bytes_from_request;
pub(crate) use commands::generate_trustee_evaluation_key_proof_from_request;
#[cfg(test)]
pub(in crate::bgv::setup) use commands::prove_trustee_evaluation_key_proof_bytes;
#[cfg(test)]
pub(crate) use commands::verify_target_decryption_share_proof_bytes_from_request;
pub(crate) use commands::verify_target_decryption_share_proof_source_from_request;
pub(crate) use commands::{
    generate_same_secret_bridge_proof_from_request, generate_vss_share_linkage_proof_from_request,
    verify_same_secret_bridge_proof_source_from_request,
    verify_vss_share_linkage_proof_material_set_from_request,
};

pub(in crate::bgv::setup) use commands::{
    VssPublicCommandCommitmentExpectation, verified_vss_share_linkage_proof_material_bytes,
    verify_vss_share_linkage_proof_source_from_request, vss_share_linkage_commitment_from_value,
};
pub(in crate::bgv::setup) use proof_codec::decode_trustee_evaluation_key_proof_from_source;
pub(in crate::bgv::setup) use proof_codec::encode_trustee_evaluation_key_proof;
pub(in crate::bgv::setup) use prover::prove_evaluation_key_share;
pub(in crate::bgv::setup) use prover::{
    VssCommittedMaterialTreeInput, vss_committed_material_column_mask_degree,
    vss_committed_material_roots_by_commitment_field,
};
pub(in crate::bgv::setup) use relation::TrusteeEvaluationKeyWitness;
pub(in crate::bgv::setup) use relation::public_key_switch_sample;
pub(in crate::bgv::setup) use relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, PUBLIC_KEY_SHARE_COMMON_REFERENCE_LABEL,
    PrivateVssShareStatement, SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE,
    SAME_SECRET_LINKAGE_ATOM_LINCHECK_REPETITIONS, SameSecretBridgeStatement,
    SameSecretLinkageAtomFieldForms, SameSecretLinkageStatement, SuccinctSetupProofContext,
    TrusteeEvaluationKeyStatement, build_same_secret_linkage_atom_field_forms,
};
pub(in crate::bgv::setup) use verifier::verify_evaluation_key_share;

#[cfg(test)]
mod tests;

use crate::{
    bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast, sub_mod_fast},
    bgv::setup::setup_proof::CanonicalProofMaterialBytes,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::hash512_hex,
};

const TRUSTEE_EVALUATION_KEY_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/trustee-evaluation-key/proof-bytes";
const PUBLIC_KEY_SHARE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/public-key-share/succinct-proof-bytes";
const PRIVATE_VSS_SHARE_PROOF_BYTES_HASH_DOMAIN: &str =
    "sealed-lattice/setup/private-vss-share/succinct-proof-bytes";

// Canonical hash of transported trustee evaluation-key proof bytes, bound into
// the package proof records and the chunked proof transport reference.
#[cfg(test)]
pub(in crate::bgv::setup) fn trustee_evaluation_key_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(
        TRUSTEE_EVALUATION_KEY_PROOF_BYTES_HASH_DOMAIN,
        &[proof_bytes],
    )
}

pub(in crate::bgv::setup) fn trustee_evaluation_key_proof_material_bytes_hash(
    proof_bytes: &CanonicalProofMaterialBytes,
) -> CanonicalResult<String> {
    proof_bytes.hash512_hex(TRUSTEE_EVALUATION_KEY_PROOF_BYTES_HASH_DOMAIN)
}

pub(crate) const TRUSTEE_EVALUATION_KEY_PROOF_FAMILY: &str = "trustee-evaluation-key";
pub(crate) const PUBLIC_KEY_SHARE_PROOF_FAMILY: &str = "public-key-share";
pub(crate) const PRIVATE_VSS_SHARE_PROOF_FAMILY: &str = "vss-opening-carry";
pub(crate) const VSS_SHARE_LINKAGE_PROOF_FAMILY: &str = "vss-share-linkage";
pub(crate) const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str = "same-secret-bridge";
pub(crate) const TARGET_DECRYPTION_SHARE_PROOF_FAMILY: &str = "target-decryption-share";
// Canonical hash of transported public-key share succinct proof bytes.
#[cfg(test)]
pub(in crate::bgv::setup) fn public_key_share_succinct_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(PUBLIC_KEY_SHARE_PROOF_BYTES_HASH_DOMAIN, &[proof_bytes])
}

pub(in crate::bgv::setup) fn public_key_share_succinct_proof_material_bytes_hash(
    proof_bytes: &CanonicalProofMaterialBytes,
) -> CanonicalResult<String> {
    proof_bytes.hash512_hex(PUBLIC_KEY_SHARE_PROOF_BYTES_HASH_DOMAIN)
}

// Canonical hash of transported private VSS succinct proof bytes.
pub(in crate::bgv::setup) fn private_vss_share_succinct_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(PRIVATE_VSS_SHARE_PROOF_BYTES_HASH_DOMAIN, &[proof_bytes])
}

pub(in crate::bgv::setup) fn private_vss_share_succinct_proof_material_bytes_hash(
    proof_bytes: &CanonicalProofMaterialBytes,
) -> CanonicalResult<String> {
    proof_bytes.hash512_hex(PRIVATE_VSS_SHARE_PROOF_BYTES_HASH_DOMAIN)
}

// Each logical length-N witness vector is split into TRACE_SPLIT physical
// columns over a trace domain of size N / TRACE_SPLIT. The split frees domain
// headroom under the guaranteed 2-adicity of the BGV primes (2^16 divides
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
// phase-one masked column is opened at most 2 * query count plus the random
// DEEP points and zero anchor (339 at the selected parameters), so 512 random
// mask coefficients cover the opened evaluations with margin at full size.
// The cap trace / 4 keeps the cubic row-check composition inside the blowup;
// development ring sizes below the full parameter set fall under the cap and are not
// zero-knowledge evidence.
pub(super) fn column_mask_degree(trace_size: usize) -> usize {
    512.min(trace_size / 4)
}
// Random out-of-domain evaluation points per limb; identity soundness per
// point is (composition degree / challenge field size), around 2^-171 at full
// size with degree-four extension challenges. A deterministic zero anchor is
// added to the DEEP evaluation list separately to bind the sumcheck residual's
// constant term.
pub(super) const DEEP_POINT_COUNT: usize = 2;
pub(super) const SUMCHECK_RESIDUAL_ANCHOR_POINT_COUNT: usize = 1;
pub(super) const DEEP_EVALUATION_POINT_COUNT: usize =
    DEEP_POINT_COUNT + SUMCHECK_RESIDUAL_ANCHOR_POINT_COUNT;
// Independent power-challenge repetitions of the linear-relation sumcheck;
// each contributes about (trace size / challenge field size), around 2^-174.
pub(super) const LINCHECK_REPETITIONS: usize = 2;
// Cross-limb witness-consistency repetitions and the bit width of the public
// integer coefficients. Narrow eight-bit coefficients keep the clear sums small
// (at most 2 * N * 255, about 2^24) so the base-3 smudging masks dominate them
// only as a bounded-leakage row. This local repetition count is not an
// end-to-end soundness or zero-knowledge estimate. Share-linkage uses the same
// twenty-repetition eight-bit schedule as the other families; the earlier
// four-40-bit schedule forced masks whose CRT lift consumed all three
// commitment fields, leaving no check field; the standard schedule keeps both
// carry and message-digit clear sums under the standard 58-digit mask so the
// lift consumes two of the three commitment fields and the third is the check
// field that catches an inconsistent per-field witness.
pub(in crate::bgv::setup) const CONSISTENCY_REPETITIONS: usize = 20;
pub(in crate::bgv::setup) const CONSISTENCY_COEFFICIENT_BITS: u32 = 8;
pub(in crate::bgv::setup) const VSS_PUBLIC_CONSISTENCY_REPETITIONS: usize = 20;
pub(in crate::bgv::setup) const VSS_PUBLIC_CONSISTENCY_COEFFICIENT_BITS: u32 = 8;
// Each consistency claim is one shared integer (clear bounded combination plus
// a family-selected mask committed digit-wise in base-3 mask columns) published
// as its residue in every proof field carrying that claim. Setup proof families
// use 58 base-3 digits, giving a ~2^92 mask bound inside the two-field lift
// window; per-claim leakage stays the clear bound over the mask bound, about
// 2^-68. This is not a 128-bit zero-knowledge row.
pub(in crate::bgv::setup) const CLAIM_MASK_RADIX: u64 = 3;
pub(in crate::bgv::setup) const CLAIM_MASK_DIGIT_COUNT: usize = 58;
// Share-linkage carry and message-trit consistency claims both take the
// standard 58-digit mask under the twenty-repetition eight-bit schedule, so
// their ~2^92 mask bound leaves the three-field lift with a check field. The
// trit-claim per-claim leakage is the clear bound over the mask bound: the
// message digit is trit-decomposed, so each claim commits a single base-three
// trit (witness bound two) and its leakage is in the standard ~2^-68 class.
pub(in crate::bgv::setup) const VSS_PUBLIC_CARRY_CLAIM_MASK_DIGIT_COUNT: usize = 58;
pub(in crate::bgv::setup) const VSS_PUBLIC_SHARE_LINKAGE_TRIT_CLAIM_MASK_DIGIT_COUNT: usize = 58;
// Same-secret-bridge digit consistency claims lift over up to seven target
// fields, so the wider eighty-seven-digit mask stays inside that CRT window
// while keeping a generous leakage margin; this constant serves the bridge
// family only (share-linkage trit claims use the 58-digit mask above).
pub(in crate::bgv::setup) const VSS_PUBLIC_DIGIT_CLAIM_MASK_DIGIT_COUNT: usize = 87;
// Target-decryption message claims need wider masks than the setup families
// because lifted aggregate-message openings have a much larger clear range. That
// clear range is fixed by the largest active target prime, which is
// DATA_PRIMES[0] at every canonical target level because the data primes
// decrease monotonically, so the aggregate-message bound is independent of how
// many target limbs are active. One hundred forty-two base-3 digits keep the
// aggregate mask inside the five-field aggregate CRT lift window with margin at
// the canonical target level. Target smudging-message claims have smaller
// witness ranges and use the shorter one hundred fourteen digit mask inside a
// four-field lift.
pub(in crate::bgv::setup) const TARGET_DECRYPTION_AGGREGATE_MESSAGE_CLAIM_MASK_DIGIT_COUNT: usize =
    142;
pub(in crate::bgv::setup) const TARGET_DECRYPTION_SMUDGING_MESSAGE_CLAIM_MASK_DIGIT_COUNT: usize =
    114;
// Experimental FRI query count at rate 1/2. Query positions are sampled
// independently with replacement; repeated positions remain separate trials
// while their Merkle openings may be deduplicated for transport. No accepted
// end-to-end soundness claim is derived from this count.
pub(super) const LOW_DEGREE_QUERY_COUNT: usize = 168;
pub(super) const MAIN_LOW_DEGREE_TRANSCRIPT_PURPOSE: &[u8] = b"batched-column-degree";
pub(super) const SUMCHECK_RESIDUAL_LOW_DEGREE_TRANSCRIPT_PURPOSE: &[u8] =
    b"sumcheck-residual-degree";
// The FRI recursion stops at a statement-derived final coefficient layer. The
// minimum keeps tiny development traces usable; the cap removes committed
// folded Merkle layers from production-size proofs while keeping final
// polynomial evaluation small relative to the opened row and hash work.
pub(super) const LOW_DEGREE_MIN_FINAL_COEFFICIENT_COUNT: usize = 32;
pub(super) const LOW_DEGREE_MAX_FINAL_COEFFICIENT_COUNT: usize = 1024;
// Smallest supported trace size keeps every domain a usable power of two.
pub(super) const MINIMUM_TRACE_SIZE: usize = 64;

pub(super) fn low_degree_final_coefficient_count(
    initial_degree_bound: usize,
) -> CanonicalResult<usize> {
    if initial_degree_bound == 0 || !initial_degree_bound.is_power_of_two() {
        return Err(invalid_succinct_setup_proof(
            "low-degree statement bound must be a power of two",
        ));
    }
    let largest_strictly_smaller_bound = initial_degree_bound / 2;
    if largest_strictly_smaller_bound < LOW_DEGREE_MIN_FINAL_COEFFICIENT_COUNT {
        return Err(invalid_succinct_setup_proof(
            "low-degree statement bound does not reach the final coefficient layer",
        ));
    }

    Ok(LOW_DEGREE_MAX_FINAL_COEFFICIENT_COUNT.min(largest_strictly_smaller_bound))
}

fn invalid_succinct_setup_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// Residue of a signed integer in [0, modulus).
pub(super) fn signed_value_residue(value: i64, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let reduced = (i128::from(value) % modulus_i128 + modulus_i128) % modulus_i128;
    u64::try_from(reduced).expect("reduced signed residue fits u64")
}
