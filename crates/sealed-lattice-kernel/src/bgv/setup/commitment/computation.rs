use super::commitment_parameters::*;
use super::matrix::*;
use super::validation::*;
use super::*;

pub(super) fn compute_setup_commitment_for_degree(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
    message_coefficients: &[u128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_source_rns_limb(source_rns_limb_index)?;
    validate_ring_degree(ring_degree)?;
    validate_message_coefficients(message_coefficients, None, ring_degree)?;
    validate_randomness_shape(randomness_by_commitment_limb, ring_degree)?;

    let limbs = compute_setup_commitment_limbs(
        public_matrix_seed_hash,
        message_coefficients,
        randomness_by_commitment_limb,
        ring_degree,
        |coefficient, modulus| {
            u64::try_from(*coefficient % u128::from(modulus)).map_err(|_| {
                invalid_commitment_input("message coefficient residue does not fit u64")
            })
        },
    )?;

    Ok(SetupCommitmentValue {
        source_rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
        limbs,
    })
}

#[cfg(test)]
pub(super) fn compute_setup_signed_lifted_commitment_for_degree(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
    message_coefficients: &[i128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_source_rns_limb(source_rns_limb_index)?;
    validate_ring_degree(ring_degree)?;
    validate_signed_message_coefficients(message_coefficients, ring_degree)?;
    validate_randomness_shape(randomness_by_commitment_limb, ring_degree)?;

    let limbs = compute_setup_commitment_limbs(
        public_matrix_seed_hash,
        message_coefficients,
        randomness_by_commitment_limb,
        ring_degree,
        |coefficient, modulus| centered_integer_to_residue(*coefficient, modulus),
    )?;

    Ok(SetupCommitmentValue {
        source_rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
        limbs,
    })
}

#[cfg(test)]
fn compute_setup_big_signed_lifted_commitment_for_degree(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
    message_coefficients: &[BigInt],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    validate_source_rns_limb(source_rns_limb_index)?;
    validate_ring_degree(ring_degree)?;
    validate_big_signed_message_coefficients(message_coefficients, ring_degree)?;
    validate_randomness_shape(randomness_by_commitment_limb, ring_degree)?;

    let limbs = compute_setup_commitment_limbs(
        public_matrix_seed_hash,
        message_coefficients,
        randomness_by_commitment_limb,
        ring_degree,
        centered_big_integer_to_residue,
    )?;

    Ok(SetupCommitmentValue {
        source_rns_limb_index,
        shamir_coefficient_index,
        ring_degree,
        limbs,
    })
}

#[cfg(test)]
pub(in super::super) fn compute_setup_big_signed_lifted_commitment(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
    message_coefficients: &[BigInt],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    compute_setup_big_signed_lifted_commitment_for_degree(
        public_matrix_seed_hash,
        source_rns_limb_index,
        shamir_coefficient_index,
        message_coefficients,
        randomness_by_commitment_limb,
        ring_degree,
    )
}

fn compute_setup_commitment_limbs<MessageCoefficient>(
    public_matrix_seed_hash: &str,
    message_coefficients: &[MessageCoefficient],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    ring_degree: usize,
    message_residue: impl Fn(&MessageCoefficient, u64) -> CanonicalResult<u64>,
) -> CanonicalResult<Vec<SetupCommitmentLimb>> {
    let mut limbs = Vec::with_capacity(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len());
    for (commitment_limb_position, commitment_modulus_index) in
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES
            .into_iter()
            .enumerate()
    {
        let modulus = DATA_PRIMES[commitment_modulus_index];
        let randomness_by_column = &randomness_by_commitment_limb[commitment_limb_position];
        let message_residues = message_coefficients
            .iter()
            .map(|coefficient| message_residue(coefficient, modulus))
            .collect::<CanonicalResult<Vec<_>>>()?;
        let randomness_residues = randomness_by_column
            .iter()
            .map(|column| {
                column
                    .iter()
                    .map(|coefficient| centered_integer_to_residue(*coefficient, modulus))
                    .collect::<CanonicalResult<Vec<_>>>()
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        let mut randomness_ntts: Vec<Option<Vec<u64>>> =
            vec![None; SETUP_COMMITMENT_RANDOMNESS_WIDTH];
        let mut rows = Vec::with_capacity(SETUP_COMMITMENT_ROW_COUNT);
        for matrix_row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
            let mut row_ntt = vec![0_u64; ring_degree];
            let mut has_sampled_matrix_product = false;
            for randomness_column_index in 0..SETUP_COMMITMENT_RANDOMNESS_WIDTH {
                if structural_matrix_polynomial_kind(matrix_row_index, randomness_column_index)
                    .is_some()
                {
                    continue;
                }
                if randomness_ntts[randomness_column_index].is_none() {
                    randomness_ntts[randomness_column_index] = Some(forward_negacyclic_ntt(
                        &randomness_residues[randomness_column_index],
                        modulus,
                    )?);
                }
                let matrix_ntt = setup_commitment_matrix_ntt(
                    public_matrix_seed_hash,
                    commitment_modulus_index,
                    matrix_row_index,
                    randomness_column_index,
                    ring_degree,
                    modulus,
                )?;
                let randomness_ntt = randomness_ntts[randomness_column_index]
                    .as_ref()
                    .expect("randomness NTT was populated before use");
                for ((accumulated_value, matrix_value), randomness_value) in row_ntt
                    .iter_mut()
                    .zip(matrix_ntt.iter())
                    .zip(randomness_ntt.iter())
                {
                    *accumulated_value = add_mod_fast(
                        *accumulated_value,
                        mul_mod_fast(*matrix_value, *randomness_value, modulus),
                        modulus,
                    );
                }
                has_sampled_matrix_product = true;
            }

            let mut row_accumulator = if has_sampled_matrix_product {
                inverse_negacyclic_ntt(&row_ntt, modulus)?
            } else {
                vec![0_u64; ring_degree]
            };
            for (randomness_column_index, randomness_column) in
                randomness_residues.iter().enumerate()
            {
                match structural_matrix_polynomial_kind(matrix_row_index, randomness_column_index) {
                    Some(StructuralMatrixPolynomial::One) => {
                        for (accumulated_value, randomness_value) in
                            row_accumulator.iter_mut().zip(randomness_column.iter())
                        {
                            *accumulated_value =
                                add_mod_fast(*accumulated_value, *randomness_value, modulus);
                        }
                    }
                    Some(StructuralMatrixPolynomial::Zero) | None => {}
                }
            }
            if matrix_row_index == SETUP_COMMITMENT_MODULE_RANK {
                for (accumulated_value, message_value) in
                    row_accumulator.iter_mut().zip(message_residues.iter())
                {
                    *accumulated_value = add_mod_fast(*accumulated_value, *message_value, modulus);
                }
            }
            rows.push(row_accumulator);
        }
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index,
            modulus,
            rows,
        });
    }

    Ok(limbs)
}

pub(crate) fn compute_setup_commitment_from_typed_opening(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
    message_coefficients: &[u128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
) -> CanonicalResult<SetupCommitmentValue> {
    compute_setup_commitment_from_typed_opening_for_degree(
        public_matrix_seed_hash,
        source_rns_limb_index,
        shamir_coefficient_index,
        message_coefficients,
        randomness_by_commitment_limb,
        POLYNOMIAL_DEGREE,
    )
}

pub(in crate::bgv::setup) fn compute_setup_commitment_from_typed_opening_for_degree(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
    message_coefficients: &[u128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    validate_fresh_randomness_by_commitment_limb(randomness_by_commitment_limb, ring_degree)?;
    compute_setup_commitment_for_degree(
        public_matrix_seed_hash,
        source_rns_limb_index,
        shamir_coefficient_index,
        message_coefficients,
        randomness_by_commitment_limb,
        ring_degree,
    )
}

#[cfg(test)]
pub(in super::super) fn compute_setup_commitment_for_tests(
    public_matrix_seed_hash: &str,
    source_rns_limb_index: usize,
    shamir_coefficient_index: u64,
    message_coefficients: &[u128],
    randomness_by_commitment_limb: &[Vec<Vec<i128>>],
    ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    compute_setup_commitment_for_degree(
        public_matrix_seed_hash,
        source_rns_limb_index,
        shamir_coefficient_index,
        message_coefficients,
        randomness_by_commitment_limb,
        ring_degree,
    )
}
