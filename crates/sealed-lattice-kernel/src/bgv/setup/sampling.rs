use super::*;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

// These JSON setup paths do not receive suite-provided sampling limits, so a
// fixed cap keeps deterministic rejection work finite.
const MAXIMUM_DETERMINISTIC_SAMPLER_CANDIDATE_DRAWS_PER_OUTPUT: u32 = 64;

fn candidate_draw_limit_exhausted_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "the BGV deterministic sampler candidate-draw limit was exhausted before deriving an output",
    )
}

fn first_accepted_candidate_from_block(
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
}
