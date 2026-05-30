use super::*;
use crate::ballot_privacy::polynomial_ring::{
    LINEAR_PROOF_MODULUS, positive_mod_linear_proof_i128,
};

#[cfg(test)]
pub(crate) fn validate_tbox_relation_builder_self_check() -> CanonicalResult<()> {
    let initial_accumulators = initialize_default_tbox_relation_accumulators()?;
    if initial_accumulators
        .primary_schwartz_zippel_accumulators
        .len()
        != 2
        || initial_accumulators
            .secondary_schwartz_zippel_accumulators
            .len()
            != 2
        || initial_accumulators.extra_beta_norm_equations.len() != 2
    {
        return Err(invalid_tbox_relation(
            "initial tbox accumulator shape does not match the default profile",
        ));
    }

    let proof_ring = tbox_proof_ring()?;
    let beta3_relation = build_default_beta3_linear_relation(1, 7)?;
    if beta3_relation.linear_terms().entries().len() != 2
        || beta3_relation.linear_terms().entries()[0].position() != tbox_beta_offset()
        || beta3_relation.linear_terms().entries()[0].coefficients()[1] != 7
        || beta3_relation.constant_term().is_some()
    {
        return Err(invalid_tbox_relation(
            "beta3 relation self-check did not match the expected layout",
        ));
    }

    let beta4_relation = build_default_beta4_linear_relation(1, 7)?;
    if beta4_relation.linear_terms().entries().len() != 2
        || beta4_relation.linear_terms().entries()[0].coefficients()[33] != proof_ring.modulus() - 7
        || beta4_relation.linear_terms().entries()[1].coefficients()[33] != 7
    {
        return Err(invalid_tbox_relation(
            "beta4 relation self-check did not match the expected layout",
        ));
    }

    let upsilon_relation = build_default_upsilon_binary_relation()?;
    if upsilon_relation.quadratic_terms().entries().len() != 1
        || upsilon_relation.linear_terms().entries().len() != 1
        || upsilon_relation.linear_terms().entries()[0]
            .coefficients()
            .iter()
            .any(|coefficient| *coefficient != proof_ring.modulus() - 1)
    {
        return Err(invalid_tbox_relation(
            "upsilon relation self-check did not match the expected layout",
        ));
    }

    let l2_relation = build_default_l2_norm_relation()?;
    if l2_relation.quadratic_terms().entries().len() != TBOX_EXACT_NORM_DIMENSION
        || l2_relation.linear_terms().entries().len() != 1
        || l2_relation.constant_term().is_none_or(|constant_term| {
            constant_term[0] != proof_ring.modulus() - TBOX_EXACT_NORM_BOUND_SQUARED
        })
    {
        return Err(invalid_tbox_relation(
            "l2 relation self-check did not match the expected layout",
        ));
    }

    let challenge_seed = [5_u8; 32];
    let prefixed_accumulators = build_default_tbox_prefix_accumulators(&challenge_seed)?;
    let folded_equations = prefixed_accumulators.auto_folded_equations()?;
    if folded_equations.len() != 4
        || folded_equations[0].quadratic_terms().entries().is_empty()
        || folded_equations[0].linear_terms().entries().is_empty()
        || folded_equations[0]
            .constant_term()
            .is_none_or(|constant_term| constant_term.len() != DEFAULT_LINEAR_PROOF_RING_DEGREE)
    {
        return Err(invalid_tbox_relation(
            "prefixed tbox accumulator self-check did not produce folded equations",
        ));
    }

    let zero_statement_matrix = PolynomialMatrix::new(
        proof_ring,
        TBOX_APPROXIMATE_NORM_COORDINATES,
        TBOX_EXACT_NORM_DIMENSION,
        vec![
            vec![0_u64; DEFAULT_LINEAR_PROOF_RING_DEGREE];
            TBOX_APPROXIMATE_NORM_COORDINATES * TBOX_EXACT_NORM_DIMENSION
        ],
    )?;
    let zero_target_vector = PolynomialVector::zero(proof_ring, TBOX_APPROXIMATE_NORM_COORDINATES)?;
    let zero_response = vec![
        vec![0_i64; DEFAULT_LINEAR_PROOF_RING_DEGREE];
        DEFAULT_LINEAR_PROOF_RING_DEGREE / TBOX_APPROXIMATE_NORM_COORDINATES
    ];
    let mut response_accumulators = prefixed_accumulators.clone();
    apply_default_tbox_z4_response_relations(
        &mut response_accumulators,
        &zero_statement_matrix,
        &zero_target_vector,
        &zero_response,
        &challenge_seed,
    )?;
    apply_default_tbox_z3_response_relations(
        &mut response_accumulators,
        &zero_statement_matrix,
        &zero_response,
        &challenge_seed,
    )?;

    Ok(())
}

pub(super) fn validate_linear_proof_z4_inputs(
    transformed_statement_matrix: &PolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    validate_statement_matrix(transformed_statement_matrix, tbox_profile)?;
    if transformed_target_vector.ring() != transformed_statement_matrix.ring()
        || transformed_target_vector.len() != transformed_statement_matrix.rows()
    {
        return Err(invalid_tbox_relation(
            "z4 response relation target vector does not match the demo transformed statement",
        ));
    }
    validate_linear_proof_response_vector(
        infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )
}

pub(super) fn validate_linear_proof_sparse_z4_inputs(
    transformed_statement_matrix: &SparsePolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
    infinity_response_vector: &[Vec<i64>],
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    validate_linear_proof_sparse_statement_matrix(transformed_statement_matrix, tbox_profile)?;
    if transformed_target_vector.ring() != transformed_statement_matrix.ring()
        || transformed_target_vector.len() != transformed_statement_matrix.rows()
    {
        return Err(invalid_tbox_relation(
            "z4 response relation target vector does not match the demo transformed statement",
        ));
    }
    validate_linear_proof_response_vector(
        infinity_response_vector,
        tbox_profile.infinity_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )
}

pub(super) fn validate_linear_proof_z3_inputs(
    transformed_statement_matrix: &PolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    validate_statement_matrix(transformed_statement_matrix, tbox_profile)?;
    validate_linear_proof_response_vector(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )
}

pub(super) fn validate_linear_proof_sparse_z3_inputs(
    transformed_statement_matrix: &SparsePolynomialMatrix,
    euclidean_response_vector: &[Vec<i64>],
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    validate_linear_proof_sparse_statement_matrix(transformed_statement_matrix, tbox_profile)?;
    validate_linear_proof_response_vector(
        euclidean_response_vector,
        tbox_profile.euclidean_response_vector_length,
        tbox_profile.proof_ring.degree(),
    )
}

pub(super) fn validate_statement_matrix(
    transformed_statement_matrix: &PolynomialMatrix,
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    let proof_ring = tbox_profile.proof_ring;
    if transformed_statement_matrix.ring() != proof_ring {
        return Err(invalid_tbox_relation(
            "response relation statement matrix does not match the demo transformed statement shape",
        ));
    }
    validate_statement_shape(
        transformed_statement_matrix.rows(),
        transformed_statement_matrix.columns(),
        tbox_profile,
    )
}

pub(super) fn validate_statement_shape(
    transformed_statement_rows: usize,
    transformed_statement_columns: usize,
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    if transformed_statement_rows == 0
        || transformed_statement_columns != tbox_profile.exact_norm_dimension()
    {
        return Err(invalid_tbox_relation(
            "response relation statement matrix does not match the demo transformed statement shape",
        ));
    }

    Ok(())
}

pub(super) fn validate_linear_proof_sparse_statement_matrix(
    transformed_statement_matrix: &SparsePolynomialMatrix,
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<()> {
    let proof_ring = tbox_profile.proof_ring;
    if transformed_statement_matrix.ring() != proof_ring {
        return Err(invalid_tbox_relation(
            "response relation statement matrix does not match the demo transformed statement shape",
        ));
    }
    validate_statement_shape(
        transformed_statement_matrix.rows(),
        transformed_statement_matrix.columns(),
        tbox_profile,
    )
}

pub(super) fn validate_linear_proof_response_vector(
    response_vector: &[Vec<i64>],
    expected_vector_length: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<()> {
    if response_vector.len() != expected_vector_length {
        return Err(invalid_tbox_relation(
            "response relation vector length does not match the demo response layout",
        ));
    }
    if response_vector
        .iter()
        .any(|polynomial| polynomial.len() != proof_ring_degree)
    {
        return Err(invalid_tbox_relation(
            "response relation polynomial degree does not match the demo proof ring",
        ));
    }

    Ok(())
}

pub(super) fn sample_linear_proof_uniform_matrix(
    row_count: usize,
    column_count: usize,
    modulus: u64,
    modulus_bit_length: usize,
    seed: &[u8; 32],
    matrix_domain_separator: u32,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let mut rows = Vec::with_capacity(row_count);
    for row_index in 0..row_count {
        let row_domain_separator = compose_linear_proof_matrix_row_domain(
            matrix_domain_separator,
            row_index
                .checked_mul(column_count)
                .ok_or_else(|| invalid_tbox_relation("matrix sampler row offset overflowed"))?,
        )?;
        rows.push(sample_linear_proof_uniform_u64_values(
            column_count,
            modulus,
            modulus_bit_length,
            seed,
            row_domain_separator,
        )?);
    }

    Ok(rows)
}

pub(super) fn compute_linear_proof_response_rotation_products(
    challenge_seed: &[u8; 32],
    challenge_matrix: &[Vec<u64>],
    column_group_count: usize,
    use_prime_rotation_domain: bool,
    modulus: u64,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let rotation_column_count = column_group_count
        .checked_mul(DEFAULT_LINEAR_PROOF_RING_DEGREE)
        .ok_or_else(|| invalid_tbox_relation("rotation product column count overflowed"))?;
    let mut signed_products =
        vec![vec![0_i128; rotation_column_count]; TBOX_QUADRATIC_EVALUATION_REPETITIONS];

    // Iterate the 256 approximate-norm projection rows. z4 (prime domain) uses
    // rows 256+index; z3 uses rows index, matching the prover's response domains.
    for response_coordinate_index in 0..256 {
        let row_domain_separator = if use_prime_rotation_domain {
            256 + response_coordinate_index
        } else {
            response_coordinate_index
        };
        for_each_linear_proof_binary_difference_nonzero(
            rotation_column_count,
            challenge_seed,
            u64::try_from(row_domain_separator)
                .map_err(|_| invalid_tbox_relation("rotation row domain does not fit in u64"))?,
            |rotation_column_index, rotation_value| {
                for repetition_index in 0..TBOX_QUADRATIC_EVALUATION_REPETITIONS {
                    let challenge =
                        i128::from(challenge_matrix[repetition_index][response_coordinate_index]);
                    signed_products[repetition_index][rotation_column_index] +=
                        challenge * i128::from(rotation_value);
                }
                Ok(())
            },
        )?;
    }

    if modulus == LINEAR_PROOF_MODULUS {
        Ok(signed_products
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| positive_mod_linear_proof_i128(*value))
                    .collect::<Vec<_>>()
            })
            .collect())
    } else {
        signed_products
            .iter()
            .map(|row| {
                row.iter()
                    .map(|value| positive_mod_i128(*value, i128::from(modulus)))
                    .collect::<CanonicalResult<Vec<_>>>()
            })
            .collect()
    }
}

// Apply the negacyclic sigma-conjugate "shift by X^{d/2}" central to the
// approximate-norm relation: scale by 1/2, then move coefficient i to i+d/2 in the
// lower half or negate it into i-d/2 in the upper half (X^{d/2}*X^i, X^d = -1).
// The 1/2 factor undoes the doubling from the conjugate sum.
pub(super) fn convert_z4_rotation_products_to_polynomials(
    ring: PolynomialRing,
    response_rotation_matrix_products: &[Vec<u64>],
    approximate_norm_coordinates: usize,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let inverse_two = ring.modulus().div_ceil(2);
    let mut rows = Vec::with_capacity(response_rotation_matrix_products.len());
    for response_rotation_product_row in response_rotation_matrix_products {
        let mut polynomial_row = vec![vec![0_u64; ring.degree()]; approximate_norm_coordinates];
        for approximate_coordinate_index in 0..approximate_norm_coordinates {
            for coefficient_index in 0..ring.degree() {
                let scaled_coefficient = multiply_mod(
                    inverse_two,
                    response_rotation_product_row
                        [approximate_coordinate_index * ring.degree() + coefficient_index],
                    ring.modulus(),
                );
                if coefficient_index < ring.degree() / 2 {
                    polynomial_row[approximate_coordinate_index]
                        [coefficient_index + ring.degree() / 2] = scaled_coefficient;
                } else {
                    polynomial_row[approximate_coordinate_index]
                        [coefficient_index - ring.degree() / 2] =
                        negate_mod(scaled_coefficient, ring.modulus());
                }
            }
        }
        rows.push(polynomial_row);
    }

    Ok(rows)
}

pub(super) fn convert_z3_rotation_products_to_polynomials(
    ring: PolynomialRing,
    response_rotation_matrix_products: &[Vec<u64>],
    extended_coordinates: usize,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut rows = Vec::with_capacity(response_rotation_matrix_products.len());
    for response_rotation_product_row in response_rotation_matrix_products {
        let mut polynomial_row = Vec::with_capacity(extended_coordinates);
        for extended_coordinate_index in 0..extended_coordinates {
            polynomial_row.push(
                response_rotation_product_row[extended_coordinate_index * ring.degree()
                    ..(extended_coordinate_index + 1) * ring.degree()]
                    .to_vec(),
            );
        }
        rows.push(polynomial_row);
    }

    Ok(rows)
}

pub(super) fn multiply_rows_by_polynomial_matrix(
    ring: PolynomialRing,
    polynomial_rows: &[Vec<Vec<u64>>],
    matrix: &PolynomialMatrix,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut output_rows = Vec::with_capacity(polynomial_rows.len());
    for polynomial_row in polynomial_rows {
        if polynomial_row.len() != matrix.rows() {
            return Err(invalid_tbox_relation(
                "polynomial row length does not match matrix row count",
            ));
        }
        let mut output_row = Vec::with_capacity(matrix.columns());
        for column_index in 0..matrix.columns() {
            let mut accumulated_polynomial = vec![0_u64; ring.degree()];
            for (row_index, row_polynomial) in polynomial_row.iter().enumerate() {
                ring.mul_negacyclic_accumulate(
                    &mut accumulated_polynomial,
                    row_polynomial,
                    matrix.entry(row_index, column_index)?,
                )?;
            }
            output_row.push(accumulated_polynomial);
        }
        output_rows.push(output_row);
    }

    Ok(output_rows)
}

pub(crate) fn multiply_rows_by_sparse_polynomial_matrix(
    ring: PolynomialRing,
    polynomial_rows: &[Vec<Vec<u64>>],
    matrix: &SparsePolynomialMatrix,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let mut output_rows = Vec::with_capacity(polynomial_rows.len());
    for polynomial_row in polynomial_rows {
        if polynomial_row.len() != matrix.rows() {
            return Err(invalid_tbox_relation(
                "polynomial row length does not match matrix row count",
            ));
        }
        let mut output_row = vec![vec![0_u64; ring.degree()]; matrix.columns()];
        for entry in matrix.entries() {
            ring.mul_negacyclic_accumulate(
                &mut output_row[entry.column_index()],
                &polynomial_row[entry.row_index()],
                entry.coefficients(),
            )?;
        }
        output_rows.push(output_row);
    }

    Ok(output_rows)
}

pub(super) fn dot_rotation_products_with_target(
    ring: PolynomialRing,
    response_rotation_matrix_products: &[Vec<u64>],
    transformed_target_vector: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    let expected_row_length = transformed_target_vector
        .len()
        .checked_mul(ring.degree())
        .ok_or_else(|| invalid_tbox_relation("target dot-product length overflowed"))?;
    let mut products = Vec::with_capacity(response_rotation_matrix_products.len());
    for row in response_rotation_matrix_products {
        if row.len() != expected_row_length {
            return Err(invalid_tbox_relation(
                "canonical vector dot-product lengths do not match",
            ));
        }

        let mut accumulated_value = 0_u64;
        for (polynomial_index, target_polynomial) in
            transformed_target_vector.entries().iter().enumerate()
        {
            let row_start = polynomial_index
                .checked_mul(ring.degree())
                .ok_or_else(|| invalid_tbox_relation("target dot-product offset overflowed"))?;
            for (rotation_coefficient, target_coefficient) in row[row_start..]
                .iter()
                .zip(target_polynomial)
                .take(ring.degree())
            {
                let product =
                    multiply_mod(*rotation_coefficient, *target_coefficient, ring.modulus());
                accumulated_value = crate::ballot_privacy::polynomial_ring::add_mod(
                    accumulated_value,
                    product,
                    ring.modulus(),
                );
            }
        }
        products.push(accumulated_value);
    }

    Ok(products)
}

pub(super) fn build_linear_proof_z4_response_relation(
    tbox_profile: TboxRelationProfile,
    ring: PolynomialRing,
    challenge_row: &[u64],
    flattened_response: &[i64],
    statement_products: &[Vec<u64>],
    target_product: u64,
) -> CanonicalResult<LinearProofQuadraticEquation> {
    if statement_products.len() < tbox_profile.exact_norm_dimension() {
        return Err(invalid_tbox_relation(
            "statement product row is too short for the z4 response relation",
        ));
    }
    let beta_offset = tbox_profile.beta_offset();
    let inverse_two = ring.modulus().div_ceil(2);
    let mut quadratic_entries = Vec::new();
    for (short_coordinate_index, statement_product) in statement_products
        .iter()
        .enumerate()
        .take(tbox_profile.exact_norm_dimension())
    {
        push_sparse_matrix_entry_if_nonzero(
            &mut quadratic_entries,
            1 + 2 * short_coordinate_index,
            beta_offset,
            ring.neg(statement_product)?,
        );
        push_sparse_matrix_entry_if_nonzero(
            &mut quadratic_entries,
            1 + 2 * short_coordinate_index,
            beta_offset + 1,
            statement_product.clone(),
        );
    }

    let mut linear_entries = Vec::new();
    for approximate_offset_index in 0..tbox_profile.approximate_relation_polynomial_count() {
        push_sparse_vector_entry_if_nonzero(
            &mut linear_entries,
            tbox_profile.y4_offset() + 1 + 2 * approximate_offset_index,
            challenge_polynomial_from_row(ring, challenge_row, approximate_offset_index)?,
        );
    }
    let scaled_target_product = multiply_mod(inverse_two, target_product, ring.modulus());
    push_sparse_vector_entry_if_nonzero(
        &mut linear_entries,
        beta_offset,
        single_coefficient_polynomial(
            ring,
            ring.degree() / 2,
            negate_mod(scaled_target_product, ring.modulus()),
        )?,
    );
    push_sparse_vector_entry_if_nonzero(
        &mut linear_entries,
        beta_offset + 1,
        single_coefficient_polynomial(ring, ring.degree() / 2, scaled_target_product)?,
    );

    LinearProofQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            ring,
            tbox_profile.quadratic_evaluation_dimension(),
            tbox_profile.quadratic_evaluation_dimension(),
            quadratic_entries,
        )?,
        SparsePolynomialVector::new(
            ring,
            tbox_profile.quadratic_evaluation_dimension(),
            linear_entries,
        )?,
        Some(constant_polynomial(
            ring,
            negate_mod(
                dot_signed_response_with_challenge(
                    flattened_response,
                    challenge_row,
                    ring.modulus(),
                )?,
                ring.modulus(),
            ),
        )),
    )
}

pub(super) fn build_linear_proof_z3_response_relation(
    tbox_profile: TboxRelationProfile,
    ring: PolynomialRing,
    challenge_row: &[u64],
    flattened_response: &[i64],
    rotation_polynomial_row: &[Vec<u64>],
) -> CanonicalResult<LinearProofQuadraticEquation> {
    if rotation_polynomial_row.len() < tbox_profile.extended_coordinates() {
        return Err(invalid_tbox_relation(
            "rotation polynomial row is too short for the z3 response relation",
        ));
    }
    let beta_offset = tbox_profile.beta_offset();
    let inverse_two = ring.modulus().div_ceil(2);
    let mut quadratic_entries = Vec::new();
    for (short_coordinate_index, rotation_polynomial) in rotation_polynomial_row
        .iter()
        .enumerate()
        .take(tbox_profile.exact_norm_dimension())
    {
        let scaled_product = ring.scale(inverse_two, rotation_polynomial)?;
        push_sparse_matrix_entry_if_nonzero(
            &mut quadratic_entries,
            1 + 2 * short_coordinate_index,
            beta_offset,
            scaled_product.clone(),
        );
        push_sparse_matrix_entry_if_nonzero(
            &mut quadratic_entries,
            1 + 2 * short_coordinate_index,
            beta_offset + 1,
            scaled_product,
        );
    }
    let scaled_upsilon_product = ring.scale(
        inverse_two,
        &rotation_polynomial_row[tbox_profile.extended_coordinates() - 1],
    )?;
    push_sparse_matrix_entry_if_nonzero(
        &mut quadratic_entries,
        tbox_profile.upsilon_offset() + 1,
        beta_offset,
        scaled_upsilon_product.clone(),
    );
    push_sparse_matrix_entry_if_nonzero(
        &mut quadratic_entries,
        tbox_profile.upsilon_offset() + 1,
        beta_offset + 1,
        scaled_upsilon_product,
    );

    let mut linear_entries = Vec::new();
    for approximate_offset_index in 0..tbox_profile.approximate_relation_polynomial_count() {
        push_sparse_vector_entry_if_nonzero(
            &mut linear_entries,
            tbox_profile.y3_offset() + 1 + 2 * approximate_offset_index,
            challenge_polynomial_from_row(ring, challenge_row, approximate_offset_index)?,
        );
    }

    LinearProofQuadraticEquation::new(
        SparsePolynomialMatrix::new(
            ring,
            tbox_profile.quadratic_evaluation_dimension(),
            tbox_profile.quadratic_evaluation_dimension(),
            quadratic_entries,
        )?,
        SparsePolynomialVector::new(
            ring,
            tbox_profile.quadratic_evaluation_dimension(),
            linear_entries,
        )?,
        Some(constant_polynomial(
            ring,
            negate_mod(
                dot_signed_response_with_challenge(
                    flattened_response,
                    challenge_row,
                    ring.modulus(),
                )?,
                ring.modulus(),
            ),
        )),
    )
}

pub(super) fn accumulate_linear_proof_repetition_relation(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    repetition_index: usize,
    relation: &LinearProofQuadraticEquation,
) -> CanonicalResult<()> {
    let weighted_relation = [WeightedLinearProofQuadraticEquation {
        challenge_scalar: 1,
        equation: relation,
    }];
    if repetition_index.is_multiple_of(2) {
        let accumulator_index = repetition_index / 2;
        accumulator_set.primary_schwartz_zippel_accumulators[accumulator_index] = accumulator_set
            .primary_schwartz_zippel_accumulators[accumulator_index]
            .accumulate_weighted_partial_equations(&weighted_relation)?;
    } else {
        let accumulator_index = repetition_index / 2;
        accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_index] = accumulator_set
            .secondary_schwartz_zippel_accumulators[accumulator_index]
            .accumulate_weighted_partial_equations(&weighted_relation)?;
    }

    Ok(())
}

pub(super) fn flatten_signed_response(
    response_vector: &[Vec<i64>],
    expected_vector_length: usize,
    proof_ring_degree: usize,
) -> CanonicalResult<Vec<i64>> {
    validate_linear_proof_response_vector(
        response_vector,
        expected_vector_length,
        proof_ring_degree,
    )?;
    Ok(response_vector
        .iter()
        .flat_map(|polynomial| polynomial.iter().copied())
        .collect())
}

pub(super) fn challenge_polynomial_from_row(
    ring: PolynomialRing,
    challenge_row: &[u64],
    polynomial_index: usize,
) -> CanonicalResult<Vec<u64>> {
    let start = polynomial_index
        .checked_mul(ring.degree())
        .ok_or_else(|| invalid_tbox_relation("challenge polynomial start overflowed"))?;
    let end = start
        .checked_add(ring.degree())
        .ok_or_else(|| invalid_tbox_relation("challenge polynomial end overflowed"))?;
    if end > challenge_row.len() {
        return Err(invalid_tbox_relation(
            "challenge polynomial index is outside the challenge row",
        ));
    }

    Ok(challenge_row[start..end].to_vec())
}

#[cfg(test)]
pub(super) fn sample_linear_proof_binary_difference_values(
    value_count: usize,
    seed: &[u8; 32],
    domain_separator: u64,
) -> CanonicalResult<Vec<i8>> {
    let mut values = vec![0_i8; value_count];
    for_each_linear_proof_binary_difference_nonzero(
        value_count,
        seed,
        domain_separator,
        |value_index, value| {
            values[value_index] = value;
            Ok(())
        },
    )?;

    Ok(values)
}

fn for_each_linear_proof_binary_difference_nonzero(
    value_count: usize,
    seed: &[u8; 32],
    domain_separator: u64,
    mut visit_nonzero: impl FnMut(usize, i8) -> CanonicalResult<()>,
) -> CanonicalResult<()> {
    let bit_count = value_count
        .checked_mul(2)
        .ok_or_else(|| invalid_tbox_relation("binary-difference bit count overflowed"))?;
    let byte_count = bit_count.div_ceil(8);
    let random_bytes =
        super::rng::generate_linear_proof_aes256ctr_stream(seed, domain_separator, byte_count);
    for value_index in 0..value_count {
        let positive_bit = (random_bytes[value_index / 8] >> (value_index % 8)) & 1;
        let negative_bit_index = value_count
            .checked_add(value_index)
            .ok_or_else(|| invalid_tbox_relation("binary-difference bit index overflowed"))?;
        let negative_bit = (random_bytes[negative_bit_index / 8] >> (negative_bit_index % 8)) & 1;
        let value = positive_bit as i8 - negative_bit as i8;
        if value != 0 {
            visit_nonzero(value_index, value)?;
        }
    }

    Ok(())
}

#[cfg(test)]
pub(super) fn read_bit(bytes: &[u8], bit_index: usize) -> CanonicalResult<u8> {
    let byte_index = bit_index / 8;
    if byte_index >= bytes.len() {
        return Err(invalid_tbox_relation(
            "binary-difference bit index is outside the sampled bytes",
        ));
    }

    Ok((bytes[byte_index] >> (bit_index % 8)) & 1)
}

pub(super) fn dot_signed_response_with_challenge(
    flattened_response: &[i64],
    challenge_row: &[u64],
    modulus: u64,
) -> CanonicalResult<u64> {
    if flattened_response.len() != challenge_row.len() {
        return Err(invalid_tbox_relation(
            "response and challenge lengths do not match for the dot product",
        ));
    }
    let mut accumulated_value = 0_i128;
    let mut accumulated_product_count = 0_usize;
    for (response_coefficient, challenge_coefficient) in
        flattened_response.iter().zip(challenge_row)
    {
        if *response_coefficient == 0 || *challenge_coefficient == 0 {
            continue;
        }
        accumulated_value += i128::from(*response_coefficient) * i128::from(*challenge_coefficient);
        accumulated_product_count += 1;
        // Lazy reduction: flush to mod q every 64 products so the i128 accumulator
        // stays bounded (64 * q * max|coeff| < 2^127) and never overflows.
        if accumulated_product_count == 64 {
            accumulated_value %= i128::from(modulus);
            accumulated_product_count = 0;
        }
    }

    positive_mod_i128(accumulated_value, i128::from(modulus))
}

pub(super) fn push_sparse_matrix_entry_if_nonzero(
    entries: &mut Vec<SparsePolynomialMatrixEntry>,
    row_index: usize,
    column_index: usize,
    polynomial: Vec<u64>,
) {
    if !is_zero_polynomial(&polynomial) {
        entries.push(SparsePolynomialMatrixEntry::new(
            row_index,
            column_index,
            polynomial,
        ));
    }
}

pub(super) fn push_sparse_vector_entry_if_nonzero(
    entries: &mut Vec<SparsePolynomialVectorEntry>,
    position: usize,
    polynomial: Vec<u64>,
) {
    if !is_zero_polynomial(&polynomial) {
        entries.push(SparsePolynomialVectorEntry::new(position, polynomial));
    }
}

pub(super) fn compose_linear_proof_matrix_row_domain(
    matrix_domain_separator: u32,
    row_offset: usize,
) -> CanonicalResult<u64> {
    let row_offset = u32::try_from(row_offset)
        .map_err(|_| invalid_tbox_relation("matrix sampler row offset does not fit in u32"))?;
    Ok((u64::from(matrix_domain_separator) << 32) | u64::from(row_offset))
}

pub(super) fn accumulate_single_linear_proof_partial_relation_by_schwartz_zippel(
    accumulator_set: &mut TboxRelationAccumulatorSet,
    relation: &LinearProofQuadraticEquation,
    challenge_seed: &[u8; 32],
    challenge_domain: u32,
    coefficient_bit_length: usize,
) -> CanonicalResult<()> {
    // This single-relation folding schedule matches the generated proof
    // transcript. Changing the challenge slot allocation invalidates current
    // generated LaZer-compatible vectors and must be treated as a proof-profile
    // change, not a local verifier hardening patch.
    for accumulator_pair_index in 0..accumulator_set.primary_schwartz_zippel_accumulators.len() {
        let challenge_values = sample_linear_proof_uniform_u64_values(
            2,
            relation.ring().modulus(),
            coefficient_bit_length,
            challenge_seed,
            u64::from(challenge_domain),
        )?;
        accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index] =
            accumulator_set.primary_schwartz_zippel_accumulators[accumulator_pair_index]
                .accumulate_weighted_partial_equations(&[WeightedLinearProofQuadraticEquation {
                    challenge_scalar: challenge_values[0],
                    equation: relation,
                }])?;
        accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index] =
            accumulator_set.secondary_schwartz_zippel_accumulators[accumulator_pair_index]
                .accumulate_weighted_partial_equations(&[WeightedLinearProofQuadraticEquation {
                    challenge_scalar: challenge_values[1],
                    equation: relation,
                }])?;
    }

    Ok(())
}

#[cfg(test)]
pub(super) fn build_default_beta3_norm_equation() -> CanonicalResult<LinearProofQuadraticEquation> {
    build_beta3_norm_equation(demo_tbox_profile()?)
}

pub(super) fn build_beta3_norm_equation(
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
    build_beta_norm_equation(false, tbox_profile)
}

#[cfg(test)]
pub(super) fn build_default_beta4_norm_equation() -> CanonicalResult<LinearProofQuadraticEquation> {
    build_beta4_norm_equation(demo_tbox_profile()?)
}

pub(super) fn build_beta4_norm_equation(
    tbox_profile: TboxRelationProfile,
) -> CanonicalResult<LinearProofQuadraticEquation> {
    build_beta_norm_equation(true, tbox_profile)
}

#[cfg(test)]
mod tests {
    use super::{read_bit, sample_linear_proof_binary_difference_values};

    #[test]
    fn binary_difference_sampling_checks_bit_bounds() {
        let seed = [7_u8; 32];
        let values = sample_linear_proof_binary_difference_values(17, &seed, 3)
            .expect("binary-difference samples");

        assert_eq!(values.len(), 17);
        assert!(values.iter().all(|value| (-1..=1).contains(value)));
        assert!(read_bit(&[0], 8).is_err());
    }
}
