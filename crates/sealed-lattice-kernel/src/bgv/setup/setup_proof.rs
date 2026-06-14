mod challenge;
mod material_transport;
#[cfg(test)]
mod proof_bit_codec;
#[cfg(test)]
mod tbox_generation;
#[cfg(test)]
mod tbox_layout;
#[cfg(test)]
mod tbox_verification;

#[cfg(test)]
pub(super) use self::challenge::derive_setup_proof_challenge_coefficients;
#[cfg(test)]
pub(crate) use self::challenge::derive_setup_proof_lnp_tbox_challenge_from_prefix;
pub(super) use self::challenge::{
    challenge_difference_invertibility_accounting_value, setup_proof_challenge_domain_hash,
    setup_proof_challenge_space_audit_hash, setup_proof_challenge_space_audit_value,
};
#[cfg(test)]
pub(super) use self::challenge::{
    derive_setup_proof_scalar_challenge, sample_setup_proof_lnp_tbox_uniform_residue_bytes,
};
pub(super) use self::material_transport::setup_proof_record_binding_value;
pub(in crate::bgv::setup) use self::material_transport::verified_setup_proof_material_chunks_from_request;
pub(crate) use self::material_transport::{
    SetupProofMaterialTransportHashes, absorb_setup_proof_material_transport_stream_chunk_request,
    begin_setup_proof_material_transport_stream_request,
    finish_setup_proof_material_transport_stream_request, setup_proof_material_transport_hashes,
};
#[cfg(test)]
pub(crate) use self::tbox_layout::{SetupProofLnpTboxLayout, private_vss_share_lnp_tbox_layout};
#[cfg(test)]
pub(crate) use self::tbox_verification::setup_proof_lnp_tbox_commitment_prefix_byte_count;
#[cfg(test)]
pub(super) use self::tbox_verification::setup_proof_lnp_tbox_h_coefficient_must_be_zero;
#[cfg(test)]
pub(crate) use self::tbox_verification::verify_setup_proof_lnp_tbox_proof_bytes;

#[cfg(test)]
use self::challenge::challenge_sample_positions;
#[cfg(test)]
use self::challenge::{
    setup_proof_lnp_tbox_challenge_material,
    setup_proof_lnp_tbox_z34_seed_and_challenge_from_prefix,
};
#[cfg(test)]
use self::proof_bit_codec::{LnpBitReader, LnpBitWriter};
#[cfg(test)]
use self::tbox_generation::setup_proof_lnp_tbox_z34_brandom_row;
#[cfg(test)]
use self::tbox_generation::{
    SetupProofLnpTboxZ34SeedMaterial, setup_proof_lnp_tbox_generated_suffix_bytes,
    setup_proof_lnp_tbox_z34_seed_material,
};
#[cfg(test)]
use self::tbox_layout::setup_proof_lnp_tbox_z34_challenge_profile_value;
#[cfg(test)]
use self::tbox_verification::{decode_lnp_tbox_gaussian_value, decode_lnp_tbox_hint_value};
#[cfg(test)]
use self::tbox_verification::{
    decode_uniform_polyvec, validate_lnp_tbox_layout, verify_lnp_tbox_h_forced_zero_coefficients,
    verify_lnp_tbox_z34_norm_bounds,
};

use num_bigint::BigUint;
use num_traits::{One, Zero};
use serde_json::{Value, json};
#[cfg(test)]
use sha3::Shake128;
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    bgv::profile::POLYNOMIAL_DEGREE,
    bgv::setup_helpers::validate_hash_string,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint},
    hashing::{HASH512_PREIMAGE_PREFIX, derive_protocol_hash, hash512, hash512_hex, to_hex},
};

#[cfg(test)]
use super::commitment::SETUP_COMMITMENT_RANDOMNESS_WIDTH;

pub(super) const SETUP_PROOF_PROFILE_ID: &str = "SealedLattice-LNP-SetupProof-v1";
pub(super) const SETUP_PROOF_CHALLENGE_BITS: u64 = 128;
pub(super) const SETUP_PROOF_CHALLENGE_COUNT: u64 = 1;
pub(super) const SETUP_PROOF_CHALLENGE_COEFFICIENT_BOUND: u64 = 2;
pub(super) const SETUP_PROOF_LNP_PROOF_RING_DEGREE: usize = 128;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE: usize = 3;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_ENCODED_BITS: u64 =
    SETUP_PROOF_LNP_PROOF_RING_DEGREE as u64 * SETUP_PROOF_LNP_CHALLENGE_LOG2_RANGE as u64;
pub(super) const SETUP_PROOF_LNP_CHALLENGE_SPACE_BITS: u64 = 147;
pub(super) const SETUP_PROOF_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-v1";
pub(super) const SETUP_PROOF_CHALLENGE_DOMAIN_PURPOSE: &str = "setup-proof-challenge-domain-v1";
pub(super) const SETUP_PROOF_CHALLENGE_SPACE: &str =
    "fixed-lnp-small-coefficient-polynomial-challenge-set";
pub(super) const SETUP_PROOF_CHALLENGE_DIFFERENCE_INVERTIBILITY_STATUS: &str =
    "repo-owned-lnp22-small-coefficient-challenge-differences-invertible";
pub(super) const SETUP_PROOF_CHALLENGE_SAMPLER: &str =
    "sealed-lattice-shake256-lazer-autostable-rejection-v1";
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS: usize = 256;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_Z34_SECURITY_PARAMETER: u64 = 128;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_NUMERATOR: u64 = 164;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_DENOMINATOR: u64 = 100;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR: u64 = 155;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR: u64 = 100;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_Z34_CHALLENGE_SEED_BYTE_COUNT: usize = 32;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_Z34_BRANDOM_K: u64 = 1;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_Z34_R_ROW_DOMAIN_START: u64 = 0;
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_Z34_RPRIME_ROW_DOMAIN_START: u64 = 256;
pub(super) const SETUP_PROOF_CHALLENGE_SEED_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-seed-v1";
pub(super) const SETUP_PROOF_CHALLENGE_STREAM_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/lnp-challenge-stream-v1";
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_LOWER_PROTOCOL_CHALLENGE_DOMAIN: &str =
    "sealed-lattice/setup/lnp-tbox-lower-protocol-challenge-v1";
#[cfg(test)]
const SETUP_PROOF_LNP_TBOX_LOWER_PROTOCOL_CHALLENGE_SEED_DOMAIN: &str =
    "sealed-lattice/setup/lnp-tbox-lower-protocol-challenge-seed-v1";
pub(super) const SETUP_PROOF_BYTES_DOMAIN: &str =
    "sealed-lattice/collective-bgv-setup/succinct-proof-bytes-v1";
pub(super) const SETUP_PROOF_SERIALIZATION: &str = "binary";
pub(crate) const SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
pub(crate) const SETUP_PROOF_MATERIAL_ENCODING: &str = "binary-chunked-proof-bytes";
const SETUP_PROOF_MATERIAL_CHUNK_MANIFEST_OBJECT_TYPE: &str = "SetupProofMaterialChunkManifest";
const SETUP_PROOF_BYTE_DECODER: &str = "sealed-lattice-succinct-setup-proof-byte-decoder-v1";
#[cfg(test)]
pub(crate) const PRIVATE_VSS_SHARE_LNP_TBOX_PARAMETER_PROFILE_ID: &str =
    "SealedLattice-LNP-PrivateVssShare-Tbox-v1";
pub(super) const SETUP_PROOF_FAMILIES: &[&str] = &["vss-opening-carry"];
// Families whose proof bytes ride the chunked setup proof-material transport:
// private VSS plus the same-secret linkage anchor, public-key share, and
// trustee evaluation-key succinct arguments. Their theorem accounting is bound
// per family rather than through the legacy LNP/tbox profile.
pub(super) const SETUP_PROOF_TRANSPORT_FAMILIES: &[&str] = &[
    "vss-opening-carry",
    "public-key-share",
    "same-secret-linkage-anchor",
    "trustee-evaluation-key",
];

#[cfg(test)]
fn setup_proof_challenge_domain_value_for_test(setup_profile_id: &str) -> Value {
    self::challenge::setup_proof_challenge_domain_value(setup_profile_id)
}

#[cfg(test)]
fn setup_proof_lnp_tbox_z34_seed_polynomial_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    if !SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS.is_multiple_of(layout.proof_ring_degree) {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 seed coefficient count must divide the proof ring degree",
        ));
    }

    Ok(SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS / layout.proof_ring_degree)
}

#[cfg(test)]
fn setup_proof_lnp_tbox_message_polynomial_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    let extension_polynomial_count = setup_proof_lnp_tbox_extension_polynomial_count(layout)?;

    layout
        .t_b_polynomial_count
        .checked_sub(extension_polynomial_count)
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP tbox tB layout is too small for z3/z4 seed material")
        })
}

#[cfg(test)]
fn setup_proof_lnp_tbox_extension_polynomial_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    let seed_polynomial_count = setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?;
    seed_polynomial_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(1))
        .and_then(|count| count.checked_add(layout.h_polynomial_count))
        .and_then(|count| count.checked_add(1))
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox extension count overflowed"))
}

#[cfg(test)]
fn setup_proof_lnp_tbox_challenge_tail_polynomial_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    layout
        .h_polynomial_count
        .checked_add(1)
        .ok_or_else(|| setup_proof_error("setup proof LNP tbox challenge-tail count overflowed"))
}

#[cfg(test)]
fn setup_proof_lnp_tbox_z3_l2_squared_bound(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<BigUint> {
    generated_lnp_tbox_z3_l2_squared_bound(layout.z3_log2_standard_deviation)
}

#[cfg(test)]
fn setup_proof_lnp_tbox_z4_infinity_norm_bound(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<BigUint> {
    generated_lnp_tbox_z4_infinity_norm_bound(layout.z4_log2_standard_deviation)
}

#[cfg(test)]
fn generated_lnp_tbox_z3_l2_squared_bound(
    log2_standard_deviation: usize,
) -> CanonicalResult<BigUint> {
    let doubled_exponent = log2_standard_deviation
        .checked_mul(2)
        .ok_or_else(|| setup_proof_error("setup proof LNP z3 bound exponent overflowed"))?;
    let seed_coefficient_count = u64::try_from(SETUP_PROOF_LNP_TBOX_Z34_SEED_TOTAL_COEFFICIENTS)
        .map_err(|_| setup_proof_error("setup proof LNP z3 seed coefficient count overflowed"))?;
    let numerator = BigUint::from(
        SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_NUMERATOR
            * SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_NUMERATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR
            * seed_coefficient_count,
    ) << doubled_exponent;
    let denominator = BigUint::from(
        SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_DENOMINATOR
            * SETUP_PROOF_LNP_TBOX_Z34_TAIL_BOUND_DENOMINATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR
            * SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR,
    );

    Ok(numerator / denominator)
}

#[cfg(test)]
fn generated_lnp_tbox_z4_infinity_norm_bound(
    log2_standard_deviation: usize,
) -> CanonicalResult<BigUint> {
    let sqrt_two_kappa = integer_square_root(
        SETUP_PROOF_LNP_TBOX_Z34_SECURITY_PARAMETER
            .checked_mul(2)
            .ok_or_else(|| setup_proof_error("setup proof LNP z4 security parameter overflowed"))?,
    )?;
    let numerator = (BigUint::from(
        sqrt_two_kappa
            .checked_mul(SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_NUMERATOR)
            .ok_or_else(|| setup_proof_error("setup proof LNP z4 bound numerator overflowed"))?,
    )) << log2_standard_deviation;
    let denominator = BigUint::from(SETUP_PROOF_LNP_TBOX_GAUSSIAN_BASE_STDDEV_DENOMINATOR);

    Ok(numerator / denominator)
}

#[cfg(test)]
fn integer_square_root(value: u64) -> CanonicalResult<u64> {
    let mut root = 0_u64;
    while root
        .checked_add(1)
        .and_then(|candidate| candidate.checked_mul(candidate))
        .is_some_and(|square| square <= value)
    {
        root += 1;
    }
    if root.checked_mul(root) != Some(value) {
        return Err(setup_proof_error(
            "setup proof LNP tbox generated bound requires an exact integer square root",
        ));
    }

    Ok(root)
}

fn setup_proof_lnp_tbox_proof_modulus() -> BigUint {
    BigUint::parse_bytes(
        b"57896044618658097711785492504343953926634992332820282019728792003956564819949",
        10,
    )
    .expect("setup proof LNP tbox proof modulus is a fixed decimal integer")
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct LnpTboxHintCoefficient {
    pub(crate) first_bit: bool,
    pub(crate) second_bit: bool,
    pub(crate) extension_zero_count: usize,
    pub(crate) value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "returned by the accepted family verifier once generated LNP tbox dimensions are pinned"
)]
pub(crate) struct LnpTboxGaussianCoefficient {
    pub(crate) unary_ones: usize,
    pub(crate) low_bits: u64,
    pub(crate) low_bit_count: usize,
    pub(crate) value: i128,
}

#[cfg(test)]
fn setup_proof_lnp_tbox_z34_row_column_count(
    layout: &SetupProofLnpTboxLayout,
    polynomial_count: usize,
    field_name: &str,
) -> CanonicalResult<usize> {
    let row_column_count = polynomial_count
        .checked_mul(layout.proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error(format!(
                "setup proof LNP tbox {field_name} row-column count overflowed"
            ))
        })?;
    if row_column_count == 0 {
        return Err(setup_proof_error(format!(
            "setup proof LNP tbox {field_name} row-column count must be positive"
        )));
    }

    Ok(row_column_count)
}

#[cfg(test)]
fn setup_proof_lnp_tbox_z34_check_window_hash(
    layout: &SetupProofLnpTboxLayout,
    field_name: &str,
    coefficients: &[LnpTboxGaussianCoefficient],
) -> CanonicalResult<String> {
    if field_name != "z3" && field_name != "z4" {
        return Err(setup_proof_error(
            "setup proof LNP tbox z3/z4 check-window field name is not accepted",
        ));
    }
    let mut encoded = Vec::new();
    append_varuint(
        &mut encoded,
        u64::try_from(coefficients.len()).map_err(|_| {
            setup_proof_error("setup proof LNP tbox z3/z4 check-window length overflowed")
        })?,
    );
    for (coefficient_index, coefficient) in coefficients.iter().enumerate() {
        append_varuint(
            &mut encoded,
            u64::try_from(coefficient_index).map_err(|_| {
                setup_proof_error(
                    "setup proof LNP tbox z3/z4 check-window coefficient index overflowed",
                )
            })?,
        );
        append_bytes(&mut encoded, coefficient.value.to_string().as_bytes());
    }

    Ok(hash512_hex(
        "sealed-lattice/setup/lnp-tbox-z34-check-window-v1",
        &[
            layout.proof_family.as_bytes(),
            layout.tbox_parameter_profile_id.as_bytes(),
            field_name.as_bytes(),
            &encoded,
        ],
    ))
}

#[cfg(test)]
fn gaussian_l2_squared(coefficients: &[LnpTboxGaussianCoefficient]) -> BigUint {
    coefficients
        .iter()
        .fold(BigUint::zero(), |sum, coefficient| {
            let magnitude = BigUint::from(coefficient.value.unsigned_abs());
            sum + (&magnitude * &magnitude)
        })
}

#[cfg(test)]
fn gaussian_infinity_norm(coefficients: &[LnpTboxGaussianCoefficient]) -> BigUint {
    coefficients
        .iter()
        .map(|coefficient| BigUint::from(coefficient.value.unsigned_abs()))
        .max()
        .unwrap_or_else(BigUint::zero)
}

#[cfg(test)]
fn setup_proof_lnp_tbox_z34_check_coefficient_count(
    layout: &SetupProofLnpTboxLayout,
) -> CanonicalResult<usize> {
    setup_proof_lnp_tbox_z34_seed_polynomial_count(layout)?
        .checked_mul(layout.proof_ring_degree)
        .ok_or_else(|| {
            setup_proof_error("setup proof LNP z3/z4 check coefficient count overflowed")
        })
}

fn setup_proof_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::ProfileComponentMismatch, message)
}

#[cfg(test)]
mod tests;
