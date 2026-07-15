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

pub(crate) use commands::generate_trustee_evaluation_key_proof_from_request;
#[cfg(test)]
pub(in crate::bgv::setup) use commands::{
    prove_trustee_evaluation_key_proof_bytes, verify_trustee_evaluation_key_proof_bytes,
};

pub(in crate::bgv::setup) use commands::{
    VssPublicCommandCommitmentExpectation, vss_share_linkage_commitment_from_value,
};
pub(in crate::bgv::setup) use fiat_shamir_transcript::HashChainTranscriptCore;
pub(in crate::bgv::setup) use merkle_commitment::{
    BatchedMerkleOpening as SetupBatchedMerkleOpening, MerkleContext as SetupMerkleContext,
    MerkleDigest as SetupMerkleDigest, MerkleTree as SetupMerkleTree,
    consistent_sorted_leaves as consistent_setup_merkle_leaves,
    sorted_unique_indices as sorted_unique_setup_merkle_indices, verify_merkle_batch_with_context,
};
pub(in crate::bgv::setup) use proof_codec::decode_trustee_evaluation_key_proof_from_source;
#[cfg(test)]
pub(in crate::bgv::setup) use proof_codec::encode_trustee_evaluation_key_proof;
#[cfg(test)]
pub(in crate::bgv::setup) use prover::prove_evaluation_key_share;
pub(in crate::bgv::setup) use relation::TrusteeEvaluationKeyWitness;
pub(in crate::bgv::setup) use relation::public_key_switch_sample;
pub(in crate::bgv::setup) use relation::{
    EvaluationKeyShareDescriptor, EvaluationKeyShareKind, PrivateVssShareStatement,
    SAME_SECRET_LINKAGE_ATOM_EXTENSION_DEGREE, SAME_SECRET_LINKAGE_ATOM_LINCHECK_REPETITIONS,
    SameSecretLinkageAtomFieldForms, SameSecretLinkageStatement, SetupProofStatement,
    SuccinctSetupProofContext, TrusteeEvaluationKeyStatement,
    build_same_secret_linkage_atom_field_forms,
};
#[cfg(test)]
pub(in crate::bgv::setup) use relation::{
    KeyBearingWitness, SameSecretLinkageWitness,
};
pub(in crate::bgv::setup) use verifier::verify_evaluation_key_share;

#[cfg(test)]
mod tests;

use crate::{
    bgv::modular_arithmetic::{add_mod_fast, mul_mod_fast, sub_mod_fast},
    bgv::setup::setup_proof::{CanonicalProofMaterialBytes, SetupProofFamily},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

#[cfg(test)]
use crate::hashing::hash512_hex;

// Canonical hash of authenticated trustee evaluation-key proof bytes, bound into
// the package proof records and the chunked proof stream reference.
#[cfg(test)]
pub(in crate::bgv::setup) fn trustee_evaluation_key_proof_bytes_hash(proof_bytes: &[u8]) -> String {
    hash512_hex(
        SetupProofFamily::TrusteeEvaluationKey
            .proof_bytes_hash_domain()
            .expect("trustee evaluation-key proofs have a byte-hash domain"),
        &[proof_bytes],
    )
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
pub(crate) const VSS_SHARE_LINKAGE_PROOF_FAMILY: &str =
    SetupProofFamily::VssShareLinkage.wire_label();
pub(crate) const SAME_SECRET_BRIDGE_PROOF_FAMILY: &str =
    SetupProofFamily::SameSecretBridge.wire_label();
#[cfg(test)]
pub(crate) const TARGET_DECRYPTION_SHARE_PROOF_FAMILY: &str =
    SetupProofFamily::TargetDecryptionShare.wire_label();
pub(crate) const TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND: i64 = 16;
#[cfg(test)]
pub(in crate::bgv::setup) fn public_key_share_succinct_proof_bytes_hash(
    proof_bytes: &[u8],
) -> String {
    hash512_hex(
        SetupProofFamily::PublicKeyShare
            .proof_bytes_hash_domain()
            .expect("public-key share proofs have a byte-hash domain"),
        &[proof_bytes],
    )
}

pub(in crate::bgv::setup) fn public_key_share_succinct_proof_material_bytes_hash(
    proof_bytes: &CanonicalProofMaterialBytes,
) -> CanonicalResult<String> {
    proof_bytes.hash512_hex(
        SetupProofFamily::PublicKeyShare
            .proof_bytes_hash_domain()
            .expect("public-key share proofs have a byte-hash domain"),
    )
}

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
pub(in crate::bgv::setup) const VSS_PUBLIC_CONSISTENCY_REPETITIONS: usize = 20;
pub(in crate::bgv::setup) const VSS_PUBLIC_CONSISTENCY_COEFFICIENT_BITS: u32 = 8;
// Each consistency claim is one shared integer: a bounded clear combination
// plus a family-selected mask committed in base-3 digit columns. Its residues
// are published in every proof field carrying the claim. The 58-digit mask fits
// inside the two-field CRT lift window, leaving another field for consistency.
pub(in crate::bgv::setup) const CLAIM_MASK_RADIX: u64 = 3;
pub(in crate::bgv::setup) const CLAIM_MASK_DIGIT_COUNT: usize = 58;
// Share-linkage carry and message-trit claims both use the 58-digit mask, so
// their lift consumes two of three commitment fields. A message claim binds one
// base-three trit with witness bound two, not a packed message digit.
pub(in crate::bgv::setup) const VSS_PUBLIC_CARRY_CLAIM_MASK_DIGIT_COUNT: usize = 58;
pub(in crate::bgv::setup) const VSS_PUBLIC_SHARE_LINKAGE_TRIT_CLAIM_MASK_DIGIT_COUNT: usize = 58;
// Same-secret-bridge target-message digit claims use all three setup
// commitment fields, so the wider eighty-seven-digit mask stays inside that
// CRT window. This leaves no independent check field for those message claims;
// their cross-field value is instead fixed by the bridge relation to the
// separately consistency-checked ternary secret and negative indicator. This
// constant serves the bridge family only (share-linkage trit claims use the
// 58-digit mask above).
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
// Integer-point asynchronous interpolation has subset-dependent rational
// weights. Multiplying every private noise polynomial by n! clears all of their
// denominators before the RNS limbs are recombined.
pub(in crate::bgv) fn target_decryption_interpolation_denominator_clearing_factor(
    participant_count: u64,
) -> CanonicalResult<u64> {
    if !super::accepted_setup::participant_count_is_supported(participant_count) {
        return Err(invalid_succinct_setup_proof(
            "target-decryption participant count is outside the supported roster range",
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

pub(super) fn signed_value_residue(value: i64, modulus: u64) -> u64 {
    let modulus_i128 = i128::from(modulus);
    let reduced = (i128::from(value) % modulus_i128 + modulus_i128) % modulus_i128;
    u64::try_from(reduced).expect("reduced signed residue fits u64")
}
