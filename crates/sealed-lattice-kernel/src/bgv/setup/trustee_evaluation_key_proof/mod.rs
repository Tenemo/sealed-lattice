// Setup-proof commands for the trustee evaluation-key atom proof and the
// recipient-private VSS proof. Public VSS linkage, threshold aggregation,
// same-secret anchoring, public-key shares, and target decryption use the common
// proof suite instead of this per-modulus engine.

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

pub(in crate::bgv::setup) use commands::{
    VssPublicCommandCommitmentExpectation, vss_share_linkage_commitment_from_value,
};
pub(in crate::bgv::setup) use fiat_shamir_transcript::HashChainTranscriptCore;
pub(in crate::bgv::setup) use merkle_commitment::{
    BatchedMerkleOpening as SetupBatchedMerkleOpening, MerkleContext as SetupMerkleContext,
    MerkleDigest as SetupMerkleDigest, consistent_sorted_leaves as consistent_setup_merkle_leaves,
    verify_merkle_batch,
};
#[cfg(test)]
pub(in crate::bgv::setup) use merkle_commitment::{
    MerkleTree as SetupMerkleTree, sorted_unique_indices as sorted_unique_setup_merkle_indices,
};
pub(in crate::bgv::setup) use proof_codec::decode_trustee_evaluation_key_proof_from_source;
#[cfg(test)]
pub(in crate::bgv::setup) use proof_codec::encode_trustee_evaluation_key_proof;
#[cfg(test)]
pub(in crate::bgv::setup) use prover::prove_evaluation_key_share;
#[cfg(test)]
pub(in crate::bgv::setup) use relation::TrusteeEvaluationKeyWitness;
#[cfg(test)]
pub(in crate::bgv::setup) use relation::generate_development_trustee_instance;
pub(in crate::bgv::setup) use relation::public_key_switch_sample;
pub(in crate::bgv::setup) use relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, PrivateVssShareStatement,
    SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE, SAME_SECRET_LINKAGE_ATOM_LINCHECK_REPETITIONS,
    SameSecretLinkageAtomFieldForms, SameSecretLinkageStatement, SetupProofStatement,
    SuccinctSetupProofContext, TrusteeEvaluationKeyStatement,
    build_same_secret_linkage_atom_field_forms,
};
pub(in crate::bgv::setup) use verifier::verify_evaluation_key_share;

#[cfg(test)]
mod tests;

use crate::{
    bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast, sub_mod_fast},
    bgv::setup::setup_proof::{CanonicalProofMaterialBytes, SetupProofFamily},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;

fn bigint_residue(value: &BigInt, modulus: u64) -> CanonicalResult<u64> {
    let modulus_integer = BigInt::from(modulus);
    let residue = ((value % &modulus_integer) + &modulus_integer) % &modulus_integer;
    residue
        .to_u64()
        .ok_or_else(|| invalid_succinct_setup_proof("masked consistency residue does not fit u64"))
}

pub(in crate::bgv::setup) fn trustee_evaluation_key_proof_material_bytes_hash(
    proof_bytes: &CanonicalProofMaterialBytes,
) -> CanonicalResult<String> {
    proof_bytes.hash512_hex(
        SetupProofFamily::TrusteeEvaluationKey
            .proof_bytes_hash_domain()
            .expect("trustee evaluation-key proofs have a byte-hash domain"),
    )
}

pub(crate) const TRUSTEE_EVALUATION_KEY_PROOF_FAMILY: &str =
    SetupProofFamily::TrusteeEvaluationKey.wire_label();
pub(crate) const PUBLIC_KEY_SHARE_PROOF_FAMILY: &str =
    SetupProofFamily::PublicKeyShare.wire_label();
pub(crate) const PRIVATE_VSS_SHARE_PROOF_FAMILY: &str =
    SetupProofFamily::PrivateVssShare.wire_label();
#[cfg(test)]
pub(crate) const TARGET_DECRYPTION_SHARE_PROOF_FAMILY: &str =
    SetupProofFamily::TargetDecryptionShare.wire_label();
#[cfg(test)]
pub(crate) const TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND: i64 = 16;
pub(in crate::bgv::setup) fn private_vss_share_succinct_proof_material_bytes_hash(
    proof_bytes: &CanonicalProofMaterialBytes,
) -> CanonicalResult<String> {
    proof_bytes.hash512_hex(
        SetupProofFamily::PrivateVssShare
            .proof_bytes_hash_domain()
            .expect("private VSS share proofs have a byte-hash domain"),
    )
}

// Split each length-N witness vector into two half-columns because the BGV
// primes guarantee only 2^16 two-adicity. The half-size trace leaves room for
// the factor-four extension coset and masked committed-degree bound while the
// batched FRI runs at rate one half.
pub(super) const TRACE_SPLIT: usize = 2;
pub(super) const DOMAIN_BLOWUP: usize = 4;
pub(super) const COMMITMENT_BOUND_FACTOR: usize = 2;
// Random Z_H-multiple mask degree per committed column. The fixed query and
// DEEP schedule opens at most 339 evaluations, while 512 coefficients leave
// margin. The trace/4 cap keeps the cubic row-check composition inside the
// committed degree bound for smaller traces.
#[cfg(test)]
pub(super) fn column_mask_degree(trace_size: usize) -> usize {
    512.min(trace_size / 4)
}
// Random out-of-domain evaluation points per limb. A deterministic zero anchor
// is added separately to bind the sumcheck residual's constant term.
pub(super) const DEEP_POINT_COUNT: usize = 2;
pub(super) const SUMCHECK_RESIDUAL_ANCHOR_POINT_COUNT: usize = 1;
pub(super) const DEEP_EVALUATION_POINT_COUNT: usize =
    DEEP_POINT_COUNT + SUMCHECK_RESIDUAL_ANCHOR_POINT_COUNT;
// Independent power-challenge repetitions of the linear-relation sumcheck.
pub(super) const LINCHECK_REPETITIONS: usize = 2;
// Cross-limb witness-consistency repetitions and public coefficient width.
// Twenty repetitions with eight-bit coefficients bound clear sums by
// 2 * N * 255. With the
// 58-digit base-3 mask, their CRT lift consumes two commitment fields and leaves
// the third to detect an inconsistent per-field witness.
pub(in crate::bgv::setup) const CONSISTENCY_REPETITIONS: usize = 20;
pub(in crate::bgv::setup) const CONSISTENCY_COEFFICIENT_BITS: u32 = 8;
// Each consistency claim is one shared integer: a bounded clear combination
// plus a family-selected mask committed in base-3 digit columns. Its residues
// are published in every proof field carrying the claim. The 58-digit mask fits
// inside the two-field CRT lift window, leaving another field for consistency.
pub(in crate::bgv::setup) const CLAIM_MASK_RADIX: u64 = 3;
pub(in crate::bgv::setup) const CLAIM_MASK_DIGIT_COUNT: usize = 58;
// Integer-point asynchronous interpolation has subset-dependent rational
// weights. Multiplying every private noise polynomial by n! clears all of their
// denominators before the RNS limbs are recombined.
#[cfg(test)]
pub(in crate::bgv) fn target_decryption_interpolation_denominator_clearing_factor(
    participant_count: u64,
) -> CanonicalResult<u64> {
    if !super::accepted_setup::participant_count_is_configurable(participant_count) {
        return Err(invalid_succinct_setup_proof(
            "target-decryption participant count is outside the configurable roster range",
        ));
    }

    (2..=participant_count).try_fold(1_u64, |product, factor| {
        product.checked_mul(factor).ok_or_else(|| {
            invalid_succinct_setup_proof(
                "target-decryption interpolation denominator-clearing factor overflowed",
            )
        })
    })
}
// Fixed shared-engine FRI query count at rate one half. Positions are sampled
// independently with replacement; repeated positions remain distinct query
// ordinals while their Merkle openings may be deduplicated for transport.
pub(super) const LOW_DEGREE_QUERY_COUNT: usize = 168;
pub(super) const MAXIMUM_FIAT_SHAMIR_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 64;
pub(super) const MAIN_LOW_DEGREE_TRANSCRIPT_PURPOSE: &[u8] = b"batched-column-degree";
pub(super) const SUMCHECK_RESIDUAL_LOW_DEGREE_TRANSCRIPT_PURPOSE: &[u8] =
    b"sumcheck-residual-degree";
// The FRI recursion stops at a statement-derived final coefficient layer. The
// minimum supports small traces; the cap avoids extra committed folded layers
// while keeping final-polynomial evaluation bounded.
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

#[cfg(test)]
pub(super) fn signed_value_residue(value: i64, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let reduced = (i128::from(value) % modulus_i128 + modulus_i128) % modulus_i128;
    u64::try_from(reduced).expect("reduced signed residue fits u64")
}
