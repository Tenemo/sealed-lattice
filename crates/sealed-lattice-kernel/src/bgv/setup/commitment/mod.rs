#[cfg(test)]
use num_bigint::BigInt;
use num_bigint::BigUint;
#[cfg(test)]
use num_traits::ToPrimitive;
use serde_json::{Value, json};

use crate::{
    bgv::{
        coefficient_codec::coefficient_vector_hash512,
        modular_arithmetic::{add_mod_fast, mul_mod_fast},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_canonical_object_hash,
};

#[cfg(test)]
mod algebra;
mod commitment_parameters;
mod computation;
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the canonical commitment decoder is live while deterministic anchor construction remains owned by later exact-family adapters and tests"
    )
)]
mod lattice_anchor;
mod matrix;
mod opening;
mod serialization;
mod validation;
mod worker_response;

#[cfg(test)]
pub(super) use algebra::*;
#[cfg(test)]
pub(super) use commitment_parameters::setup_coefficient_fits_commitment_modulus_product;
use commitment_parameters::setup_coefficients_fit_commitment_modulus_product;
pub(crate) use commitment_parameters::{
    SETUP_COMMITMENT_HIDING_ERROR_WIDTH, SETUP_COMMITMENT_HIDING_SECRET_WIDTH,
    SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES,
    SETUP_COMMITMENT_RANDOMNESS_WIDTH,
};
pub(super) use commitment_parameters::{
    SETUP_COMMITMENT_ROW_COUNT, setup_commitment_randomness_coefficient_bound,
    setup_commitment_randomness_distribution_purpose,
};
#[cfg(test)]
use commitment_parameters::{
    setup_big_signed_coefficient_fits_centered_commitment_modulus_product,
    setup_signed_coefficient_fits_centered_commitment_modulus_product,
};
pub(super) use matrix::*;
#[cfg(test)]
pub(super) use opening::*;
pub(super) use serialization::*;

pub(crate) use computation::compute_setup_commitment_from_typed_opening;
#[cfg(test)]
pub(super) use computation::{
    compute_setup_big_signed_lifted_commitment, compute_setup_commitment_for_tests,
    compute_setup_commitment_from_typed_opening_for_degree,
};
#[cfg(test)]
use computation::{
    compute_setup_commitment_for_degree, compute_setup_signed_lifted_commitment_for_degree,
};
pub(crate) use lattice_anchor::parse_lattice_anchor_commitment_canonical_bytes;
#[cfg(test)]
pub(crate) use lattice_anchor::{
    LatticeAnchorCommitment, lattice_anchor_commitment_canonical_bytes,
};
pub(crate) use worker_response::setup_commitment_worker_response_bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum StructuralMatrixPolynomial {
    Zero,
    One,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupCommitmentLimb {
    pub(super) commitment_modulus_index: usize,
    pub(super) modulus: u64,
    pub(super) rows: Vec<Vec<u64>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SetupCommitmentValue {
    pub(super) source_rns_limb_index: usize,
    pub(super) shamir_coefficient_index: u64,
    pub(super) ring_degree: usize,
    pub(super) limbs: Vec<SetupCommitmentLimb>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SetupCommitmentOpeningVerification {
    pub(super) commitment_root: String,
    pub(super) randomness_infinity_bound: i128,
    pub(super) message_coefficient_bound: u128,
}

fn invalid_commitment_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use super::{
        SETUP_COMMITMENT_HIDING_SECRET_WIDTH, SETUP_COMMITMENT_RANDOMNESS_WIDTH,
        compute_setup_commitment_for_degree,
        compute_setup_commitment_from_typed_opening_for_degree,
        compute_setup_signed_lifted_commitment_for_degree,
        setup_coefficient_fits_commitment_modulus_product, setup_commitment_matrix_polynomial,
        setup_commitment_root, verify_setup_commitment_opening,
        verify_setup_lifted_commitment_opening, verify_setup_signed_lifted_commitment_opening,
    };
    use crate::{
        bgv::{
            modular_arithmetic::{add_mod_fast, mul_mod_fast},
            parameters::DATA_PRIMES,
        },
        encoding::CanonicalResult,
    };

    const TEST_RING_DEGREE: usize = 8;
    const TEST_RANDOMNESS_INFINITY_BOUND: i128 = 1;

    #[test]
    fn commitment_matrix_sampler_rejects_a_modulus_outside_its_coordinate() {
        let error =
            setup_commitment_matrix_polynomial(&valid_hash('0'), 0, 0, 0, TEST_RING_DEGREE, 0)
                .expect_err("a matrix coordinate cannot select the zero modulus");

        assert!(error.message.contains("does not match"));
    }

    #[test]
    fn commitment_opening_verifies_and_rejects_tampering() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('a');
        let message = message_coefficients();
        let randomness = randomness_columns(TEST_RANDOMNESS_INFINITY_BOUND);
        let commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            2,
            &message,
            &randomness,
            TEST_RING_DEGREE,
        )?;

        let verification = verify_setup_commitment_opening(
            &public_matrix_seed_hash,
            &commitment,
            &message,
            &randomness,
            TEST_RANDOMNESS_INFINITY_BOUND,
        )?;

        assert_eq!(
            verification.commitment_root,
            setup_commitment_root(&commitment)?
        );
        assert_eq!(verification.message_coefficient_bound, u128::from(34_u64));

        let mut tampered_commitment = commitment.clone();
        tampered_commitment.limbs[0].rows[0][0] =
            (tampered_commitment.limbs[0].rows[0][0] + 1) % tampered_commitment.limbs[0].modulus;
        assert!(
            verify_setup_commitment_opening(
                &public_matrix_seed_hash,
                &tampered_commitment,
                &message,
                &randomness,
                TEST_RANDOMNESS_INFINITY_BOUND,
            )
            .is_err()
        );

        let mut out_of_range_message = message;
        out_of_range_message[3] = u128::from(DATA_PRIMES[0]);
        assert!(
            verify_setup_commitment_opening(
                &public_matrix_seed_hash,
                &commitment,
                &out_of_range_message,
                &randomness,
                TEST_RANDOMNESS_INFINITY_BOUND,
            )
            .is_err()
        );

        Ok(())
    }

    #[test]
    fn typed_commitment_derives_source_domain_from_limb_index() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('e');
        let message = message_coefficients();
        let randomness = randomness_columns(1);
        let commitment = compute_setup_commitment_from_typed_opening_for_degree(
            &public_matrix_seed_hash,
            0,
            1,
            &message,
            &randomness,
            TEST_RING_DEGREE,
        )?;
        assert_eq!(commitment.source_rns_limb_index, 0);
        assert_eq!(commitment.shamir_coefficient_index, 1);

        Ok(())
    }

    #[test]
    fn typed_commitment_rejects_an_out_of_range_source_limb() {
        let public_matrix_seed_hash = valid_hash('f');
        assert!(
            compute_setup_commitment_from_typed_opening_for_degree(
                &public_matrix_seed_hash,
                DATA_PRIMES.len(),
                1,
                &message_coefficients(),
                &randomness_columns(1),
                TEST_RING_DEGREE,
            )
            .is_err()
        );
    }

    #[test]
    fn commitment_uses_only_the_opening_tape_for_each_commitment_limb() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('9');
        let message = message_coefficients();
        let baseline_randomness = randomness_columns(1);
        let mut changed_randomness = baseline_randomness.clone();
        changed_randomness[1][0][0] = match changed_randomness[1][0][0] {
            -1 => 1,
            _ => -1,
        };

        let baseline_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            0,
            &message,
            &baseline_randomness,
            TEST_RING_DEGREE,
        )?;
        let changed_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            0,
            &message,
            &changed_randomness,
            TEST_RING_DEGREE,
        )?;

        assert_eq!(baseline_commitment.limbs[0], changed_commitment.limbs[0]);
        assert_ne!(baseline_commitment.limbs[1], changed_commitment.limbs[1]);
        assert_eq!(baseline_commitment.limbs[2], changed_commitment.limbs[2]);
        Ok(())
    }

    #[test]
    fn typed_commitment_rejects_one_opening_tape_shared_across_commitment_limbs() {
        let one_opening_tape = vec![randomness_columns(1)[0].clone()];
        assert!(
            compute_setup_commitment_from_typed_opening_for_degree(
                &valid_hash('8'),
                0,
                0,
                &message_coefficients(),
                &one_opening_tape,
                TEST_RING_DEGREE,
            )
            .is_err()
        );
    }

    #[test]
    fn typed_commitment_enforces_the_all_ternary_fresh_opening_profile() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('7');
        let ternary_randomness = fresh_randomness_columns();
        let compute = |randomness: &[Vec<Vec<i128>>]| {
            compute_setup_commitment_from_typed_opening_for_degree(
                &public_matrix_seed_hash,
                0,
                0,
                &message_coefficients(),
                randomness,
                TEST_RING_DEGREE,
            )
        };

        compute(&ternary_randomness)?;

        let mut ternary_out_of_support = ternary_randomness.clone();
        ternary_out_of_support[0][0][0] = 2;
        let ternary_error =
            compute(&ternary_out_of_support).expect_err("purpose-11 value two must be rejected");
        assert!(ternary_error.message.contains("purpose 11 support"));

        let mut hiding_error_out_of_support = ternary_randomness;
        hiding_error_out_of_support[0][SETUP_COMMITMENT_HIDING_SECRET_WIDTH][0] = -2;
        let hiding_error = compute(&hiding_error_out_of_support)
            .expect_err("purpose-12 value minus two must be rejected");
        assert!(hiding_error.message.contains("purpose 12 support"));
        Ok(())
    }

    #[test]
    fn signed_lifted_commitment_opening_accepts_centered_messages() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('d');
        let signed_message = vec![-21, -13, -8, -5, 0, 5, 8, 13];
        let randomness = shifted_randomness_columns();
        let commitment = compute_setup_signed_lifted_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            4,
            &signed_message,
            &randomness,
            TEST_RING_DEGREE,
        )?;

        let verification = verify_setup_signed_lifted_commitment_opening(
            &public_matrix_seed_hash,
            &commitment,
            &signed_message,
            &randomness,
            1,
        )?;

        assert_eq!(verification.message_coefficient_bound, 21);
        assert_eq!(
            verification.commitment_root,
            setup_commitment_root(&commitment)?
        );
        let unsigned_message = signed_message
            .iter()
            .map(|coefficient| u128::try_from(*coefficient).unwrap_or(0))
            .collect::<Vec<_>>();
        assert!(
            verify_setup_lifted_commitment_opening(
                &public_matrix_seed_hash,
                &commitment,
                &unsigned_message,
                &randomness,
                1,
            )
            .is_err(),
            "unsigned lifted opening must not reinterpret centered negative responses as zero"
        );

        Ok(())
    }

    #[test]
    fn commitment_homomorphism_preserves_lifted_integer_combination() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('b');
        let first_message = message_coefficients();
        let second_message = vec![u128::from(DATA_PRIMES[0] - 3), 1, 4, 1, 5, 9, 2, 6];
        let first_randomness = randomness_columns(1);
        let second_randomness = shifted_randomness_columns();

        let first_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            1,
            &first_message,
            &first_randomness,
            TEST_RING_DEGREE,
        )?;
        let second_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            1,
            &second_message,
            &second_randomness,
            TEST_RING_DEGREE,
        )?;

        let combined_message = first_message
            .iter()
            .zip(second_message.iter())
            .map(|(first_value, second_value)| (3 * first_value) + (5 * second_value))
            .collect::<Vec<_>>();
        let combined_randomness = first_randomness
            .iter()
            .zip(second_randomness.iter())
            .map(|(first_limb, second_limb)| {
                first_limb
                    .iter()
                    .zip(second_limb.iter())
                    .map(|(first_column, second_column)| {
                        first_column
                            .iter()
                            .zip(second_column.iter())
                            .map(|(first_value, second_value)| {
                                (3 * first_value) + (5 * second_value)
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let direct_combined_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            1,
            &combined_message,
            &combined_randomness,
            TEST_RING_DEGREE,
        )?;
        let homomorphic_combination =
            combine_commitments_for_test(&first_commitment, &second_commitment, 3, 5);

        assert_eq!(homomorphic_combination, direct_combined_commitment);
        assert!(
            combined_message
                .iter()
                .all(|coefficient| setup_coefficient_fits_commitment_modulus_product(*coefficient))
        );
        assert!(
            combined_message
                .iter()
                .any(|coefficient| *coefficient >= u128::from(DATA_PRIMES[0]))
        );
        assert!(
            verify_setup_commitment_opening(
                &public_matrix_seed_hash,
                &direct_combined_commitment,
                &combined_message,
                &combined_randomness,
                8,
            )
            .is_err(),
            "combined lifted openings are outside the source q_l coefficient range and require the VSS carry relation"
        );

        Ok(())
    }

    fn message_coefficients() -> Vec<u128> {
        vec![0, 1, 2, 3, 5, 8, 13, 34]
    }

    fn randomness_columns(bound: i128) -> Vec<Vec<Vec<i128>>> {
        super::SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .iter()
            .enumerate()
            .map(|(commitment_limb_position, _)| {
                (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                    .map(|column_index| {
                        (0..TEST_RING_DEGREE)
                            .map(|coefficient_index| {
                                ((commitment_limb_position + column_index + coefficient_index)
                                    as i128
                                    % ((2 * bound) + 1))
                                    - bound
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }

    fn shifted_randomness_columns() -> Vec<Vec<Vec<i128>>> {
        super::SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .iter()
            .enumerate()
            .map(|(commitment_limb_position, _)| {
                (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                    .map(|column_index| {
                        (0..TEST_RING_DEGREE)
                            .map(|coefficient_index| {
                                match (commitment_limb_position
                                    + column_index
                                    + (2 * coefficient_index))
                                    % 3
                                {
                                    0 => -1,
                                    1 => 0,
                                    _ => 1,
                                }
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }

    fn fresh_randomness_columns() -> Vec<Vec<Vec<i128>>> {
        super::SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .iter()
            .enumerate()
            .map(|(commitment_limb_position, _)| {
                (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
                    .map(|column_index| {
                        (0..TEST_RING_DEGREE)
                            .map(|coefficient_index| {
                                let support_position =
                                    commitment_limb_position + column_index + coefficient_index;
                                match support_position % 3 {
                                    0 => -1,
                                    1 => 0,
                                    _ => 1,
                                }
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect()
    }

    fn combine_commitments_for_test(
        first_commitment: &super::SetupCommitmentValue,
        second_commitment: &super::SetupCommitmentValue,
        first_scalar: u64,
        second_scalar: u64,
    ) -> super::SetupCommitmentValue {
        let mut combined = first_commitment.clone();
        for ((combined_limb, first_limb), second_limb) in combined
            .limbs
            .iter_mut()
            .zip(first_commitment.limbs.iter())
            .zip(second_commitment.limbs.iter())
        {
            for ((combined_row, first_row), second_row) in combined_limb
                .rows
                .iter_mut()
                .zip(first_limb.rows.iter())
                .zip(second_limb.rows.iter())
            {
                for ((combined_value, first_value), second_value) in combined_row
                    .iter_mut()
                    .zip(first_row.iter())
                    .zip(second_row.iter())
                {
                    let modulus = combined_limb.modulus;
                    *combined_value = add_mod_fast(
                        mul_mod_fast(*first_value, first_scalar % modulus, modulus),
                        mul_mod_fast(*second_value, second_scalar % modulus, modulus),
                        modulus,
                    );
                }
            }
        }

        combined
    }

    fn valid_hash(fill: char) -> String {
        fill.to_string().repeat(128)
    }
}
