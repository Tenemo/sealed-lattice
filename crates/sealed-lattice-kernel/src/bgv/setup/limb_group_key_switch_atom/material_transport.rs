//! Homomorphic material-transport commitments for the key-switch atoms.
//!
//! Each trustee's public key-switch material (the recombined `A` and `B` per
//! atom) is large: about 32 GB across ten trustees for the full schedule. It
//! does not need to travel publicly. This module commits each trustee's material
//! with an additively homomorphic commitment, so:
//!
//!  - each trustee's atom proofs bind their own material commitment (the atom
//!    statement's `materialRoot`), rather than shipping raw material; and
//!  - the published aggregate runtime key is checked against the homomorphic sum
//!    of the per-trustee material commitments: `commit(sum_i m_i) = sum_i
//!    commit(m_i)`, so a verifier confirms the aggregate equals the sum of the
//!    committed per-trustee materials without ever receiving the per-trustee raw
//!    component stores.
//!
//! The commitment reuses the same flat proof-field Ajtai construction as the
//! linear opening (a fixed public matrix expanded from a seed); it is linear, so
//! the aggregate check is exact. This is the design demonstration and the
//! aggregate-sum check; the transport byte model is in the material-transport
//! decision record. Test-gated; not on any acceptance path.

use super::linear_opening::{FlatCommitment, LinearOpeningParameters, commit_flat};
use super::proof_field::ProofFieldParameters;

/// Commits one trustee's material vector (no hiding randomness needed for public
/// material; a zero randomness vector keeps the homomorphism exact).
pub(crate) fn commit_material<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitment_parameters: &LinearOpeningParameters,
    material: &[[u64; LIMB_COUNT]],
) -> FlatCommitment<LIMB_COUNT> {
    let randomness = vec![parameters.zero(); commitment_parameters.randomness_length];
    commit_flat(parameters, commitment_parameters, material, &randomness)
}

/// Homomorphic sum of per-trustee commitments, `sum_i commit(m_i)`.
pub(crate) fn homomorphic_sum<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    commitments: &[FlatCommitment<LIMB_COUNT>],
) -> FlatCommitment<LIMB_COUNT> {
    let rank = commitments
        .first()
        .map(|commitment| commitment.rows.len())
        .unwrap_or(0);
    let mut rows = vec![parameters.zero(); rank];
    for commitment in commitments {
        for (accumulator, row) in rows.iter_mut().zip(commitment.rows.iter()) {
            *accumulator = parameters.add(accumulator, row);
        }
    }
    FlatCommitment { rows }
}

/// Sums per-trustee material vectors coordinatewise into the aggregate material.
pub(crate) fn aggregate_material<const LIMB_COUNT: usize>(
    parameters: &ProofFieldParameters<LIMB_COUNT>,
    materials: &[Vec<[u64; LIMB_COUNT]>],
) -> Vec<[u64; LIMB_COUNT]> {
    let length = materials
        .first()
        .map(|material| material.len())
        .unwrap_or(0);
    let mut aggregate = vec![parameters.zero(); length];
    for material in materials {
        for (accumulator, value) in aggregate.iter_mut().zip(material.iter()) {
            *accumulator = parameters.add(accumulator, value);
        }
    }
    aggregate
}

/// The aggregate check: `commit(aggregate) == sum_i commit(m_i)`. A verifier
/// runs this with the per-trustee commitments (compact) and the published
/// aggregate material commitment, never the per-trustee raw stores.
pub(crate) fn aggregate_matches_homomorphic_sum<const LIMB_COUNT: usize>(
    aggregate_commitment: &FlatCommitment<LIMB_COUNT>,
    per_trustee_commitments: &[FlatCommitment<LIMB_COUNT>],
    parameters: &ProofFieldParameters<LIMB_COUNT>,
) -> bool {
    let sum = homomorphic_sum(parameters, per_trustee_commitments);
    aggregate_commitment.rows == sum.rows
}

#[cfg(test)]
mod tests {
    use super::super::proof_field::sixteen_limb_group_field_parameters;
    use super::*;

    fn material<const LIMB_COUNT: usize>(
        parameters: &ProofFieldParameters<LIMB_COUNT>,
        length: usize,
        seed: u64,
    ) -> Vec<[u64; LIMB_COUNT]> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                parameters.unsigned_word_to_element(state)
            })
            .collect()
    }

    #[test]
    fn published_aggregate_matches_homomorphic_sum_of_committed_materials() {
        let parameters = sixteen_limb_group_field_parameters();
        let length = 40;
        let commitment_parameters = LinearOpeningParameters {
            commitment_rank: 8,
            witness_length: length,
            randomness_length: 6,
            matrix_seed: 0x3ec0,
            mask_bound: 1,
        };

        // Ten trustees' public materials.
        let materials = (0..10)
            .map(|trustee| material(&parameters, length, 0x100 + trustee as u64))
            .collect::<Vec<_>>();
        let per_trustee_commitments = materials
            .iter()
            .map(|trustee_material| {
                commit_material(&parameters, &commitment_parameters, trustee_material)
            })
            .collect::<Vec<_>>();

        // The runtime aggregate key material and its commitment.
        let aggregate = aggregate_material(&parameters, &materials);
        let aggregate_commitment = commit_material(&parameters, &commitment_parameters, &aggregate);

        // The verifier check: aggregate commitment equals the homomorphic sum of
        // the per-trustee commitments, without the raw per-trustee stores.
        assert!(
            aggregate_matches_homomorphic_sum(
                &aggregate_commitment,
                &per_trustee_commitments,
                &parameters,
            ),
            "published aggregate must equal the homomorphic sum of committed materials"
        );

        // A tampered aggregate (one trustee's material altered after committing)
        // must break the check.
        let mut tampered_materials = materials.clone();
        tampered_materials[3][7] = parameters.add(
            &tampered_materials[3][7],
            &parameters.unsigned_word_to_element(1),
        );
        let tampered_aggregate = aggregate_material(&parameters, &tampered_materials);
        let tampered_aggregate_commitment =
            commit_material(&parameters, &commitment_parameters, &tampered_aggregate);
        assert!(
            !aggregate_matches_homomorphic_sum(
                &tampered_aggregate_commitment,
                &per_trustee_commitments,
                &parameters,
            ),
            "an aggregate that does not equal the committed per-trustee sum must be rejected"
        );
    }
}
