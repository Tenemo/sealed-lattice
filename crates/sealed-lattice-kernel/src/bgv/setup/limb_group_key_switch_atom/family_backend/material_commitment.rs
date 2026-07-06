//! Compact commitment over transported evaluation-key material.
//!
//! One deterministic ring commitment (the estimator-backed instance in
//! `witness_commitment`: rank 8, 32-bit modulus, seeded XOF matrix) binds a
//! trustee's per-limb key-switch component material, so the atom proofs can
//! bind a short `materialRoot` instead of requiring the raw multi-gigabyte
//! store on the proof path. The material is public, so the randomness block is
//! zero and the commitment is deterministic and recomputable by any verifier
//! holding the material.
//!
//! Encoding: every transported residue (below its 47-bit limb prime) splits
//! into a low and a high 24-bit half, each a valid commitment-ring coefficient;
//! halves pack into degree-256 ring elements in transport order. The
//! commitment is linear in the message block, so summing per-trustee
//! commitments equals committing the coefficient-wise integer sum of their
//! material - the mechanics behind the aggregate check (a full-roster sum of
//! halves stays far below the commitment modulus, so the integer sum is exact;
//! the published runtime aggregate is reduced modulo each limb prime, so the
//! aggregate comparison also carries the public wrap multiples of the limb
//! prime, encoded the same way).

use super::super::negacyclic_transform::NegacyclicDomain;
use super::super::proof_field::ProofFieldParameters;
use super::super::witness_commitment::{
    WITNESS_COMMITMENT_RANDOMNESS_RANK, WITNESS_COMMITMENT_RING_DEGREE, WitnessCommitment,
    commit_witness, witness_commitment_parameters,
};
use super::merkle::MerkleDigest;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::hash256;

const MATERIAL_ROOT_DOMAIN: &str =
    "sealed-lattice/setup/key-switch-atom/material-commitment-root-v1";
// Each transported residue is below its data prime, and every data prime is a
// 47-bit prime (between 2^46 and 2^47), so a residue splits into a low and a
// high 24-bit half, each a valid commitment-ring coordinate below 2^24. The
// componentwise sum of a supported roster (at most twenty trustees) of such
// halves stays below 20 * 2^24 < 2^29, well under the 32-bit commitment
// modulus, so the roster sum commits with no carry.
const HALF_BITS: u32 = 24;
const HALF_MASK: u64 = (1 << HALF_BITS) - 1;

fn invalid_material(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

// Split transported residues into 23-bit halves and pack them into
// degree-256 commitment-ring elements, zero-padding the tail.
fn pack_material_message(
    parameters: &ProofFieldParameters<1>,
    residues: impl Iterator<Item = u64>,
) -> CanonicalResult<Vec<Vec<[u64; 1]>>> {
    let ring_degree = WITNESS_COMMITMENT_RING_DEGREE;
    let mut elements = Vec::new();
    let mut current = Vec::with_capacity(ring_degree);
    for residue in residues {
        if residue >> (2 * HALF_BITS) != 0 {
            return Err(invalid_material(
                "material residue exceeds the two-half commitment encoding",
            ));
        }
        for half in [residue & HALF_MASK, residue >> HALF_BITS] {
            current.push(parameters.unsigned_word_to_element(half));
            if current.len() == ring_degree {
                elements.push(std::mem::replace(
                    &mut current,
                    Vec::with_capacity(ring_degree),
                ));
            }
        }
    }
    if !current.is_empty() {
        current.resize(ring_degree, parameters.zero());
        elements.push(current);
    }
    if elements.is_empty() {
        return Err(invalid_material("material commitment requires residues"));
    }
    Ok(elements)
}

// Commit one key's transported per-limb component material
// (`component_b_by_digit[digit][limb][coefficient]`) deterministically under
// `seed` (public material: zero randomness).
pub(crate) fn commit_key_material(
    seed: u64,
    component_b_by_digit: &[Vec<Vec<u64>>],
) -> CanonicalResult<WitnessCommitment> {
    let parameters = witness_commitment_parameters();
    let domain = NegacyclicDomain::new(&parameters, WITNESS_COMMITMENT_RING_DEGREE)
        .map_err(|_| invalid_material("commitment ring domain builds"))?;
    let residues = component_b_by_digit
        .iter()
        .flat_map(|digit| digit.iter().flat_map(|limb| limb.iter().copied()));
    let message = pack_material_message(&parameters, residues)?;
    let zero_randomness = vec![
        vec![parameters.zero(); WITNESS_COMMITMENT_RING_DEGREE];
        WITNESS_COMMITMENT_RANDOMNESS_RANK
    ];
    Ok(commit_witness(
        &parameters,
        &domain,
        seed,
        &message,
        &zero_randomness,
    ))
}

// The short binding root over a material commitment, in transform-domain row
// order, length-framed per row.
pub(crate) fn material_commitment_root(commitment: &WitnessCommitment) -> MerkleDigest {
    let mut row_bytes = Vec::new();
    for row in commitment {
        for value in row {
            row_bytes.extend_from_slice(&value[0].to_le_bytes());
        }
    }
    hash256(
        MATERIAL_ROOT_DOMAIN,
        &[&(commitment.len() as u64).to_le_bytes(), &row_bytes],
    )
}

// Componentwise sum of material commitments (the message block is linear, so
// this equals committing the coefficient-wise integer sum of the material).
pub(crate) fn sum_material_commitments(
    commitments: &[WitnessCommitment],
) -> CanonicalResult<WitnessCommitment> {
    let parameters = witness_commitment_parameters();
    let first = commitments
        .first()
        .ok_or_else(|| invalid_material("commitment sum requires at least one commitment"))?;
    let mut accumulator = first.clone();
    for commitment in &commitments[1..] {
        if commitment.len() != accumulator.len() {
            return Err(invalid_material("commitment row counts must match"));
        }
        for (accumulated_row, row) in accumulator.iter_mut().zip(commitment.iter()) {
            if row.len() != accumulated_row.len() {
                return Err(invalid_material("commitment row lengths must match"));
            }
            for (accumulated, value) in accumulated_row.iter_mut().zip(row.iter()) {
                *accumulated = parameters.add(accumulated, value);
            }
        }
    }
    Ok(accumulator)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_material(
        seed: u64,
        digits: usize,
        limbs: usize,
        degree: usize,
    ) -> Vec<Vec<Vec<u64>>> {
        let mut state = seed;
        (0..digits)
            .map(|_| {
                (0..limbs)
                    .map(|_| {
                        (0..degree)
                            .map(|_| {
                                state = state
                                    .wrapping_mul(6_364_136_223_846_793_005)
                                    .wrapping_add(1);
                                state % (1 << 46)
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn material_commitment_is_deterministic_and_binding_to_bytes() {
        let material = synthetic_material(7, 2, 3, 64);
        let commitment = commit_key_material(0x5eed, &material).expect("commits");
        let again = commit_key_material(0x5eed, &material).expect("commits");
        assert_eq!(
            material_commitment_root(&commitment),
            material_commitment_root(&again),
            "the public material commitment must be deterministic"
        );

        // One flipped residue changes the commitment root.
        let mut tampered = material.clone();
        tampered[1][2][7] ^= 1;
        let tampered_commitment = commit_key_material(0x5eed, &tampered).expect("commits");
        assert_ne!(
            material_commitment_root(&commitment),
            material_commitment_root(&tampered_commitment),
            "a tampered residue must change the material root"
        );

        // A different seed is a different matrix.
        let other_seed = commit_key_material(0x5eee, &material).expect("commits");
        assert_ne!(
            material_commitment_root(&commitment),
            material_commitment_root(&other_seed),
            "a different seed must change the material root"
        );
    }

    #[test]
    fn material_commitments_sum_homomorphically() {
        // commit(a) + commit(b) equals commit(a + b) when the coefficient-wise
        // sum stays inside the two-half encoding (the aggregate mechanics).
        let first = synthetic_material(1, 2, 2, 64);
        let second = synthetic_material(2, 2, 2, 64);
        let seed = 0xa11e;
        // The halves of a sum are not the sums of halves in general (carry
        // across the 23-bit boundary), so the homomorphism is checked over the
        // ENCODED message: sum the commitments and compare against committing
        // the summed HALVES encoding. Both sides use the same packing, so this
        // is exactly the linearity the aggregate check relies on.
        let commitment_first = commit_key_material(seed, &first).expect("commits");
        let commitment_second = commit_key_material(seed, &second).expect("commits");
        let summed_commitments =
            sum_material_commitments(&[commitment_first, commitment_second]).expect("sums");

        // Recommit the integer-summed material only when no half crosses the
        // 23-bit boundary; the synthetic values above are full-range, so build
        // a carry-free pair explicitly for the equality half of the test.
        let small_first = synthetic_material(3, 1, 2, 32)
            .into_iter()
            .map(|digit| {
                digit
                    .into_iter()
                    .map(|limb| limb.into_iter().map(|value| value % (1 << 22)).collect())
                    .collect()
            })
            .collect::<Vec<Vec<Vec<u64>>>>();
        let small_second = synthetic_material(4, 1, 2, 32)
            .into_iter()
            .map(|digit| {
                digit
                    .into_iter()
                    .map(|limb| limb.into_iter().map(|value| value % (1 << 22)).collect())
                    .collect()
            })
            .collect::<Vec<Vec<Vec<u64>>>>();
        let small_sum: Vec<Vec<Vec<u64>>> = small_first
            .iter()
            .zip(small_second.iter())
            .map(|(digit_a, digit_b)| {
                digit_a
                    .iter()
                    .zip(digit_b.iter())
                    .map(|(limb_a, limb_b)| {
                        limb_a
                            .iter()
                            .zip(limb_b.iter())
                            .map(|(a, b)| a + b)
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let small_summed_commitment = sum_material_commitments(&[
            commit_key_material(seed, &small_first).expect("commits"),
            commit_key_material(seed, &small_second).expect("commits"),
        ])
        .expect("sums");
        let committed_sum = commit_key_material(seed, &small_sum).expect("commits");
        assert_eq!(
            material_commitment_root(&small_summed_commitment),
            material_commitment_root(&committed_sum),
            "carry-free material sums must commit homomorphically"
        );

        // And the full-range pair still sums deterministically (mechanics), and
        // tampering one input commitment breaks the sum.
        let tampered_sum = sum_material_commitments(&[
            commit_key_material(seed, &first).expect("commits"),
            commit_key_material(seed + 1, &second).expect("commits"),
        ])
        .expect("sums");
        assert_ne!(
            material_commitment_root(&summed_commitments),
            material_commitment_root(&tampered_sum),
            "a tampered input commitment must change the aggregate sum"
        );
    }

    #[test]
    fn material_commitment_encodes_real_data_prime_residues_and_pins_the_two_half_ceiling() {
        // The real Q_share primes are 47-bit (between 2^46 and 2^47), so their
        // residues reach past the retired 23-bit half boundary (2^46). Commit
        // material whose residues are the largest canonical residue for each
        // data prime, exercising the 24-bit half encoding on the actual
        // parameters instead of synthetic sub-2^46 values.
        let digits = 2;
        let limbs = 3;
        let degree = 64;
        let material: Vec<Vec<Vec<u64>>> = (0..digits)
            .map(|_| {
                (0..limbs)
                    .map(|limb_index| {
                        let prime = crate::bgv::parameters::DATA_PRIMES[limb_index];
                        assert!(
                            prime > (1_u64 << 46),
                            "data primes must exceed the retired 23-bit half boundary"
                        );
                        (0..degree)
                            .map(|coefficient_index| prime - 1 - (coefficient_index as u64 % 4))
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let commitment =
            commit_key_material(0x5eed, &material).expect("commits real 47-bit-prime residues");
        let again = commit_key_material(0x5eed, &material).expect("commits");
        assert_eq!(
            material_commitment_root(&commitment),
            material_commitment_root(&again),
            "real-prime material commitment must be deterministic"
        );

        // A residue at the two-half ceiling (2^48 - 1) is still a valid pair of
        // 24-bit halves; a residue at 2^48 overflows the encoding and must be
        // refused. This pins the boundary so a future narrowing of the halves
        // cannot silently start rejecting real residues.
        let mut at_ceiling = material.clone();
        at_ceiling[0][0][0] = (1_u64 << (2 * HALF_BITS)) - 1;
        commit_key_material(0x5eed, &at_ceiling).expect("commits the two-half ceiling residue");
        let mut over_ceiling = material;
        over_ceiling[0][0][0] = 1_u64 << (2 * HALF_BITS);
        assert!(
            commit_key_material(0x5eed, &over_ceiling).is_err(),
            "a residue at or above the two-half ceiling must be refused"
        );
    }
}
