use super::super::*;
use super::*;

// Transpose action of the automorphism matrix on a public vector:
// (M_phi^T u)_i = u[i*g mod 2N] with the negacyclic sign fold, so that
// <u, phi_g(s)> = <M_phi^T u, s>.
pub(crate) fn galois_automorphism_transpose_apply(
    vector: &[u64],
    galois_element: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let degree = vector.len();
    let ring_order = 2 * degree;
    if galois_element.is_multiple_of(2) {
        return Err(invalid_succinct_setup_proof("Galois element must be odd"));
    }
    let mut transposed = Vec::with_capacity(degree);
    for index in 0..degree {
        // The element acts modulo 2N, so a full-profile schedule value reduces
        // to a valid automorphism on a smaller ring; the target >= N branch is
        // the negacyclic X^N = -1 sign fold.
        let target = (index * galois_element) % ring_order;
        if target < degree {
            transposed.push(vector[target]);
        } else {
            transposed.push(sub_mod_fast(0, vector[target - degree], modulus));
        }
    }

    Ok(transposed)
}

// Deterministic public key-switch sample for one digit and limb, matching the
// production sampler framing exactly.
pub(crate) fn public_key_switch_sample(
    key_switch_domain: &str,
    key_switch_seed_hex: &str,
    digit_index: usize,
    modulus: u64,
    ring_degree: usize,
) -> Vec<u64> {
    let digit_bytes = (digit_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    DeterministicSampler::new(
        KEY_SWITCH_SAMPLE_DOMAIN,
        &[
            key_switch_domain.as_bytes(),
            key_switch_seed_hex.as_bytes(),
            &digit_bytes,
            &modulus_bytes,
        ],
    )
    .uniform_residues(modulus, ring_degree)
}

// Per-coordinate transpose product: the matrix stays in the base field, so a
// transpose action on an extension vector is the base action on each of the
// four challenge extension coordinates.
pub(crate) fn negacyclic_transpose_product_extension(
    matrix_polynomial: &[u64],
    vector: &[ChallengeExtensionElement],
    modulus: u64,
) -> CanonicalResult<Vec<ChallengeExtensionElement>> {
    let mut result = vec![ChallengeExtensionTower::zero(); vector.len()];
    let mut coordinate_vector = vec![0_u64; vector.len()];
    for coordinate in 0..CHALLENGE_EXTENSION_DEGREE {
        for (slot, element) in coordinate_vector.iter_mut().zip(vector.iter()) {
            *slot = element[coordinate];
        }
        let transposed =
            negacyclic_transpose_product(matrix_polynomial, &coordinate_vector, modulus)?;
        for (target, value) in result.iter_mut().zip(transposed.iter()) {
            target[coordinate] = *value;
        }
    }

    Ok(result)
}
