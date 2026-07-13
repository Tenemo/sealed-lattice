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
    hashing::{derive_canonical_object_hash, hash_framed_parts_512 as hash512},
};

use super::sampling::reduce_unbiased_u64;

#[cfg(test)]
mod algebra;
mod commitment_parameters;
mod computation;
mod matrix;
mod opening;
mod serialization;
mod validation;

#[cfg(test)]
pub(super) use algebra::*;
pub(super) use commitment_parameters::*;
pub(super) use matrix::*;
#[cfg(test)]
pub(super) use opening::*;
pub(super) use serialization::*;

pub(crate) use computation::compute_setup_commitment_from_opening_request;
#[cfg(test)]
pub(super) use computation::{
    compute_setup_big_signed_lifted_commitment, compute_setup_commitment_for_tests,
};
#[cfg(test)]
use computation::{
    compute_setup_commitment_for_degree, compute_setup_signed_lifted_commitment_for_degree,
};

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
pub(super) struct SetupCommitmentValue {
    pub(super) source_rns_limb_index: usize,
    pub(super) source_message_modulus: u64,
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
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        SETUP_COMMITMENT_RANDOMNESS_WIDTH, compute_setup_commitment_for_degree,
        compute_setup_commitment_from_opening_request,
        compute_setup_signed_lifted_commitment_for_degree,
        setup_coefficient_fits_commitment_modulus_product, setup_commitment_root,
        verify_setup_commitment_opening, verify_setup_lifted_commitment_opening,
        verify_setup_signed_lifted_commitment_opening,
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
    fn commitment_opening_verifies_and_rejects_tampering() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('a');
        let message = message_coefficients();
        let randomness = randomness_columns(TEST_RANDOMNESS_INFINITY_BOUND);
        let commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
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
    fn commitment_command_computes_canonical_roots() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('e');
        let message = message_coefficients();
        let randomness = randomness_columns(1);
        let response = compute_setup_commitment_from_opening_request(&json!({
            "command": "ComputeSetupCommitmentFromOpening",
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "sourceRnsLimbIndex": 0,
            "sourceMessageModulus": DATA_PRIMES[0],
            "shamirCoefficientIndex": 1,
            "messageCoefficients": message,
            "randomnessByColumn": randomness,
            "ringDegree": TEST_RING_DEGREE,
        }))?;

        assert_eq!(
            response["commitmentRoot"]
                .as_str()
                .expect("commitment root")
                .len(),
            128
        );

        Ok(())
    }

    #[test]
    fn commitment_command_rejects_wrong_source_prime() {
        let public_matrix_seed_hash = valid_hash('f');
        let mut wrong_prime_request = json!({
            "command": "ComputeSetupCommitmentFromOpening",
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "sourceRnsLimbIndex": 0,
            "sourceMessageModulus": DATA_PRIMES[0],
            "shamirCoefficientIndex": 1,
            "messageCoefficients": message_coefficients(),
            "randomnessByColumn": randomness_columns(1),
            "ringDegree": TEST_RING_DEGREE,
        });
        wrong_prime_request["sourceMessageModulus"] = json!(DATA_PRIMES[1]);
        assert!(compute_setup_commitment_from_opening_request(&wrong_prime_request).is_err());
    }

    #[test]
    fn signed_lifted_commitment_opening_accepts_centered_messages() -> CanonicalResult<()> {
        let public_matrix_seed_hash = valid_hash('d');
        let signed_message = vec![-21, -13, -8, -5, 0, 5, 8, 13];
        let randomness = shifted_randomness_columns();
        let commitment = compute_setup_signed_lifted_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
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
            DATA_PRIMES[0],
            1,
            &first_message,
            &first_randomness,
            TEST_RING_DEGREE,
        )?;
        let second_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
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
            .map(|(first_column, second_column)| {
                first_column
                    .iter()
                    .zip(second_column.iter())
                    .map(|(first_value, second_value)| (3 * first_value) + (5 * second_value))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let direct_combined_commitment = compute_setup_commitment_for_degree(
            &public_matrix_seed_hash,
            0,
            DATA_PRIMES[0],
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

    fn randomness_columns(bound: i128) -> Vec<Vec<i128>> {
        (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
            .map(|column_index| {
                (0..TEST_RING_DEGREE)
                    .map(|coefficient_index| {
                        ((column_index + coefficient_index) as i128 % ((2 * bound) + 1)) - bound
                    })
                    .collect()
            })
            .collect()
    }

    fn shifted_randomness_columns() -> Vec<Vec<i128>> {
        (0..SETUP_COMMITMENT_RANDOMNESS_WIDTH)
            .map(|column_index| {
                (0..TEST_RING_DEGREE)
                    .map(
                        |coefficient_index| match (column_index + (2 * coefficient_index)) % 3 {
                            0 => -1,
                            1 => 0,
                            _ => 1,
                        },
                    )
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
