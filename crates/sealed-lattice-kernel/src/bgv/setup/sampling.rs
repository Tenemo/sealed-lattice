use super::*;

use sha3::{
    CShake256, CShake256Core,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::transcript_core::decode_hex;

#[cfg(all(test, not(target_arch = "wasm32")))]
use rayon::prelude::*;

// These JSON setup paths do not receive suite-provided sampling limits, so a
// fixed cap keeps deterministic rejection work finite.
pub(super) const MAXIMUM_DETERMINISTIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 64;

/// Samples one complete public role-coordinate stream from the ceremony's
/// public setup seed. The customization bytes already contain the canonical
/// `PublicSetupSamplerCustomization` tuple, so this function owns the common
/// cSHAKE and fixed-width modular-rejection mechanics without knowing a
/// relation-specific coordinate grammar.
pub(super) fn sample_public_setup_residues(
    public_setup_seed_hex: &str,
    canonical_customization_bytes: &[u8],
    modulus: u64,
    output_count: usize,
) -> CanonicalResult<Vec<u64>> {
    if modulus <= 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "public setup sampling modulus must be greater than one",
        ));
    }
    if output_count == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public setup sampling output count must be positive",
        ));
    }
    if canonical_customization_bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "public setup sampler customization must be nonempty",
        ));
    }

    let public_setup_seed = decode_hex(public_setup_seed_hex)?;
    if public_setup_seed.len() != 64 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public setup seed must contain exactly 64 bytes",
        ));
    }

    // The profile deliberately uses bitLength(m), rather than bitLength(m-1).
    // For example modulus 256 therefore consumes two bytes, matching the
    // canonical private sampler rule and its exact zero-rejection case.
    let modulus_bit_length = u64::BITS - modulus.leading_zeros();
    let candidate_byte_length =
        usize::try_from(modulus_bit_length.div_ceil(8)).map_err(|_| public_sampler_size_error())?;
    let maximum_stream_byte_length = output_count
        .checked_mul(
            usize::try_from(MAXIMUM_DETERMINISTIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT)
                .map_err(|_| public_sampler_size_error())?,
        )
        .and_then(|value| value.checked_mul(candidate_byte_length))
        .ok_or_else(public_sampler_size_error)?;
    maximum_stream_byte_length
        .checked_mul(8)
        .ok_or_else(public_sampler_size_error)?;

    let mut hasher = CShake256::from_core(CShake256Core::new(canonical_customization_bytes));
    hasher.update(&public_setup_seed);
    let mut reader = hasher.finalize_xof();

    let candidate_space_size = 1_u128
        .checked_shl(
            u32::try_from(candidate_byte_length * 8).map_err(|_| public_sampler_size_error())?,
        )
        .ok_or_else(public_sampler_size_error)?;
    let modulus_wide = u128::from(modulus);
    let accepted_candidate_count = (candidate_space_size / modulus_wide) * modulus_wide;
    let mut residues = Vec::with_capacity(output_count);
    let mut consumed_stream_byte_length = 0_usize;

    for _ in 0..output_count {
        let mut accepted_residue = None;
        for _ in 0..MAXIMUM_DETERMINISTIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT {
            let mut candidate_bytes = [0_u8; 8];
            reader.read(&mut candidate_bytes[..candidate_byte_length]);
            consumed_stream_byte_length = consumed_stream_byte_length
                .checked_add(candidate_byte_length)
                .ok_or_else(public_sampler_size_error)?;
            if consumed_stream_byte_length > maximum_stream_byte_length {
                return Err(public_sampler_size_error());
            }

            let candidate = u128::from(u64::from_le_bytes(candidate_bytes));
            if candidate < accepted_candidate_count {
                accepted_residue = Some(
                    u64::try_from(candidate % modulus_wide)
                        .map_err(|_| public_sampler_size_error())?,
                );
                break;
            }
        }
        residues.push(accepted_residue.ok_or_else(candidate_draw_limit_exhausted_error)?);
    }

    Ok(residues)
}

fn public_sampler_size_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "public setup sampler byte-length arithmetic exceeds the supported profile",
    )
}

pub(super) fn candidate_draw_limit_exhausted_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "the BGV deterministic sampler candidate-draw limit was exhausted before deriving an output",
    )
}

#[cfg(test)]
pub(super) fn first_accepted_candidate_from_block(
    output: &[u8; 64],
    modulus: u64,
    candidate_draw_count: &mut u32,
    maximum_candidate_draws_per_output: u32,
) -> CanonicalResult<Option<u64>> {
    for chunk in output.chunks_exact(8) {
        if *candidate_draw_count == maximum_candidate_draws_per_output {
            return Err(candidate_draw_limit_exhausted_error());
        }
        *candidate_draw_count += 1;
        let mut word = [0_u8; 8];
        word.copy_from_slice(chunk);
        if let Some(reduced_value) = reduce_unbiased_u64(u64::from_le_bytes(word), modulus) {
            return Ok(Some(reduced_value));
        }
    }

    if *candidate_draw_count == maximum_candidate_draws_per_output {
        Err(candidate_draw_limit_exhausted_error())
    } else {
        Ok(None)
    }
}

#[cfg(test)]
pub(super) fn dense_public_residues(
    seed_hash: &str,
    label: &str,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    dense_public_residues_with_degree(seed_hash, label, modulus, POLYNOMIAL_DEGREE)
}

// Same per-position framing as `dense_public_residues` over an explicit
// degree, so reduced development rings derive a prefix of the full-ring
// residues instead of a differently framed vector.
#[cfg(test)]
pub(super) fn dense_public_residues_with_degree(
    seed_hash: &str,
    label: &str,
    modulus: u64,
    ring_degree: usize,
) -> CanonicalResult<Vec<u64>> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        (0..ring_degree)
            .into_par_iter()
            .map(|position| sample_residue(seed_hash, label, position, modulus))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        (0..ring_degree)
            .map(|position| sample_residue(seed_hash, label, position, modulus))
            .collect()
    }
}

// Polynomial multiplication in Z_q[X]/(X^N + 1): forward NTT both operands,
// multiply pointwise, then inverse NTT.
#[cfg(test)]
pub(super) fn negacyclic_product_mod(
    left: &[u64],
    right: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let mut left_ntt = left.to_vec();
    let mut right_ntt = right.to_vec();
    forward_negacyclic_ntt_in_place(&mut left_ntt, modulus)?;
    forward_negacyclic_ntt_in_place(&mut right_ntt, modulus)?;
    for (left_value, right_value) in left_ntt.iter_mut().zip(right_ntt.iter()) {
        *left_value = mul_mod(*left_value, *right_value, modulus)?;
    }
    inverse_negacyclic_ntt_in_place(&mut left_ntt, modulus)?;

    Ok(left_ntt)
}

#[cfg(test)]
pub(super) fn sample_residue(
    seed_hash: &str,
    label: &str,
    position: usize,
    modulus: u64,
) -> CanonicalResult<u64> {
    if modulus == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "public-residue sampling modulus must be positive",
        ));
    }
    let position_text = position.to_string();
    let modulus_text = modulus.to_string();
    let mut block_index = 0_u64;
    let mut candidate_draw_count = 0_u32;
    while candidate_draw_count < MAXIMUM_DETERMINISTIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT {
        let block_index_text = block_index.to_string();
        let output = hash512(
            "sealed-lattice-bgv-rns/sample-residue",
            &[
                seed_hash.as_bytes(),
                label.as_bytes(),
                position_text.as_bytes(),
                modulus_text.as_bytes(),
                block_index_text.as_bytes(),
            ],
        );
        if let Some(reduced_value) = first_accepted_candidate_from_block(
            &output,
            modulus,
            &mut candidate_draw_count,
            MAXIMUM_DETERMINISTIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT,
        )? {
            return Ok(reduced_value);
        }
        block_index = block_index
            .checked_add(1)
            .ok_or_else(candidate_draw_limit_exhausted_error)?;
    }

    Err(candidate_draw_limit_exhausted_error())
}

#[cfg(test)]
pub(super) fn reduce_unbiased_u64(candidate: u64, modulus: u64) -> Option<u64> {
    if modulus == 0 {
        return None;
    }
    let modulus = u128::from(modulus);
    // Rejection sampling: accept only the largest multiple of the modulus below
    // 2^64 so the reduction is bias-free; None means resample.
    let accepted_candidate_count = ((1_u128 << 64) / modulus) * modulus;
    let candidate = u128::from(candidate);
    if candidate < accepted_candidate_count {
        Some(u64::try_from(candidate % modulus).expect("reduced candidate fits u64"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_sampler_candidate_draw_exhaustion_is_typed_and_deterministic() {
        let rejected_candidates = [u8::MAX; 64];
        let mut candidate_draw_count = 0;
        let error = first_accepted_candidate_from_block(
            &rejected_candidates,
            (1_u64 << 63) + 1,
            &mut candidate_draw_count,
            8,
        )
        .expect_err("all eight fixed candidates are in the rejection zone");

        assert_eq!(candidate_draw_count, 8);
        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("candidate-draw limit was exhausted"));
    }

    #[test]
    fn zero_public_sampler_modulus_is_rejected_without_looping() {
        let error = sample_residue(&"0".repeat(128), "invalid-modulus", 0, 0)
            .expect_err("a zero modulus cannot define a residue distribution");

        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("modulus must be positive"));
    }

    #[test]
    fn public_setup_sampler_rejects_overflow_before_allocating() {
        let error = sample_public_setup_residues(
            &"00".repeat(64),
            b"nonempty canonical customization",
            u64::MAX,
            usize::MAX,
        )
        .expect_err("an impossible logical stream length must refuse before allocation");

        assert_eq!(error.code, CanonicalErrorCode::InvalidProtocolObject);
        assert!(error.message.contains("byte-length arithmetic"));
    }

    #[test]
    fn public_setup_sampler_rejects_noncanonical_seed_hex() {
        let error = sample_public_setup_residues(
            &"AA".repeat(64),
            b"nonempty canonical customization",
            257,
            1,
        )
        .expect_err("uppercase seed hex is not canonical");

        assert_eq!(error.code, CanonicalErrorCode::InvalidHex);
    }
}
