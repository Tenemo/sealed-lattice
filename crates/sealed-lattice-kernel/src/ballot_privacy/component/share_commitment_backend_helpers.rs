use super::*;

use crate::ballot_privacy::linear_proof::statement::{
    rotate_left_negacyclic_signed_polynomial, source_modulus_inverse_mod_proof_modulus,
    split_source_polynomial_into_proof_ring_with_coefficient_representation,
};

pub(crate) fn derive_share_commitment_message_matrix(
    share_commitment_profile_hash: &str,
) -> Result<Vec<Vec<u64>>, ComponentProofBackendError> {
    (0..SHARE_COMMITMENT_MODULE_RANK)
        .map(|row_index| {
            derive_share_commitment_polynomial(
                "sealed.vote/internal/share-commitment/message-matrix-v1",
                &json!({
                    "rowIndex": row_index,
                    "shareCommitmentProfileHash": share_commitment_profile_hash,
                }),
            )
        })
        .collect()
}

pub(crate) fn derive_share_commitment_randomness_matrix(
    share_commitment_profile_hash: &str,
) -> Result<Vec<Vec<Vec<u64>>>, ComponentProofBackendError> {
    (0..SHARE_COMMITMENT_MODULE_RANK)
        .map(|row_index| {
            (0..SHARE_COMMITMENT_OPENING_DIMENSION)
                .map(|column_index| {
                    derive_share_commitment_polynomial(
                        "sealed.vote/internal/share-commitment/randomness-matrix-v1",
                        &json!({
                            "columnIndex": column_index,
                            "rowIndex": row_index,
                            "shareCommitmentProfileHash": share_commitment_profile_hash,
                        }),
                    )
                })
                .collect()
        })
        .collect()
}

pub(crate) fn derive_share_commitment_polynomial(
    domain: &str,
    payload: &Value,
) -> Result<Vec<u64>, ComponentProofBackendError> {
    let mut polynomial = Vec::with_capacity(SHARE_COMMITMENT_MODULE_DEGREE);
    for coefficient_index in 0..SHARE_COMMITMENT_MODULE_DEGREE {
        polynomial.push(derive_share_commitment_uniform_number(
            domain,
            &json!({
                "coefficientIndex": coefficient_index,
                "payload": payload,
            }),
        )?);
    }

    Ok(polynomial)
}

// Rejection sampling for an unbiased uniform value mod q: rejection_limit = 2^64 - (2^64 mod q)
// is the largest multiple of q below 2^64; words at or above it are discarded to avoid modulo bias.
pub(crate) fn derive_share_commitment_uniform_number(
    domain: &str,
    payload: &Value,
) -> Result<u64, ComponentProofBackendError> {
    let unsigned_word_modulus = 1u128 << 64;
    let rejection_limit =
        unsigned_word_modulus - (unsigned_word_modulus % u128::from(SHARE_COMMITMENT_MODULUS));
    let mut block_counter = 0_u64;

    loop {
        let block = derive_share_commitment_bytes(
            domain,
            &json!({
                "blockCounter": block_counter,
                "payload": payload,
            }),
            64,
        )?;
        for chunk in block.chunks_exact(8) {
            let candidate = u64::from_le_bytes(chunk.try_into().map_err(|_| {
                ComponentProofBackendError::invalid(
                    "Share-commitment uniform chunk has invalid length.",
                )
            })?);
            if u128::from(candidate) < rejection_limit {
                return Ok((u128::from(candidate) % u128::from(SHARE_COMMITMENT_MODULUS)) as u64);
            }
        }
        block_counter = block_counter.checked_add(1).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Share-commitment uniform derivation counter overflowed.",
            )
        })?;
    }
}

pub(crate) fn derive_share_commitment_bytes(
    domain: &str,
    payload: &Value,
    byte_length: usize,
) -> Result<Vec<u8>, ComponentProofBackendError> {
    let mut output = vec![0_u8; byte_length];
    let mut output_offset = 0_usize;
    let mut block_counter = 0_u64;
    while output_offset < byte_length {
        let block_payload = json!({
            "blockCounter": block_counter,
            "payload": payload,
        });
        let canonical = canonical_json(&block_payload).map_err(|error| {
            ComponentProofBackendError::invalid(format!(
                "Share-commitment expansion payload is not canonical: {error}"
            ))
        })?;
        let block = hash512(domain, &[canonical.as_bytes()]);
        let bytes_to_copy = block.len().min(byte_length - output_offset);
        output[output_offset..output_offset + bytes_to_copy]
            .copy_from_slice(&block[..bytes_to_copy]);
        output_offset += bytes_to_copy;
        block_counter = block_counter.checked_add(1).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Share-commitment byte derivation counter overflowed.",
            )
        })?;
    }

    Ok(output)
}

// Coefficients of m(X)*X^k mod (X^n+1): a straight index shift for non-wrapping terms, with the
// wraparound terms negated because X^n = -1 in this negacyclic ring.
pub(crate) fn share_commitment_message_entry_polynomial(
    message_matrix_polynomial: &[u64],
    share_coordinate_index: usize,
) -> Vec<u64> {
    (0..SHARE_COMMITMENT_MODULE_DEGREE)
        .map(|output_coefficient_index| {
            if output_coefficient_index >= share_coordinate_index {
                message_matrix_polynomial[output_coefficient_index - share_coordinate_index]
                    % SHARE_COMMITMENT_MODULUS
            } else {
                negate_share_commitment_coefficient(
                    message_matrix_polynomial[SHARE_COMMITMENT_MODULE_DEGREE
                        + output_coefficient_index
                        - share_coordinate_index],
                )
            }
        })
        .collect()
}

pub(crate) fn negate_share_commitment_coefficient(coefficient: u64) -> u64 {
    if coefficient == 0 {
        0
    } else {
        SHARE_COMMITMENT_MODULUS - coefficient
    }
}

pub(crate) fn negate_share_commitment_polynomial(polynomial: &[u64]) -> Vec<u64> {
    polynomial
        .iter()
        .map(|coefficient| negate_share_commitment_coefficient(*coefficient))
        .collect()
}

// Coefficient-stride ring split: decomposes Z_q[X]/(X^256+1) into split_factor copies of a
// lower-degree ring by interleaving coefficients (split_polynomial[j][i] = polynomial[sf*i + j]).
pub(crate) fn split_share_commitment_polynomial(
    polynomial: &[u64],
    split_polynomial_degree: usize,
) -> Result<Vec<Vec<u64>>, ComponentProofBackendError> {
    if polynomial.len() != SHARE_COMMITMENT_MODULE_DEGREE
        || split_polynomial_degree == 0
        || !SHARE_COMMITMENT_MODULE_DEGREE.is_multiple_of(split_polynomial_degree)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment polynomial cannot be split into the requested source ring.",
        ));
    }
    let split_factor = SHARE_COMMITMENT_MODULE_DEGREE / split_polynomial_degree;
    let mut split_polynomials = vec![vec![0_u64; split_polynomial_degree]; split_factor];
    for (split_index, split_polynomial) in split_polynomials.iter_mut().enumerate() {
        for (coefficient_index, coefficient) in split_polynomial.iter_mut().enumerate() {
            *coefficient = polynomial[split_factor * coefficient_index + split_index];
        }
    }

    Ok(split_polynomials)
}

pub(crate) fn push_share_commitment_sparse_entry(
    entries: &mut Vec<SparsePolynomialMatrixEntry>,
    row_index: usize,
    column_index: usize,
    coefficients: Vec<u64>,
) {
    if coefficients.iter().any(|coefficient| *coefficient != 0) {
        entries.push(SparsePolynomialMatrixEntry::new(
            row_index,
            column_index,
            coefficients,
        ));
    }
}

#[cfg(test)]
pub(crate) fn add_structured_constant_entry(
    coefficients_by_position: &mut BTreeMap<(usize, usize), u64>,
    row_index: usize,
    column_index: usize,
    coefficient: u64,
) -> Result<(), ComponentProofBackendError> {
    if coefficient >= RECEIVER_ENCRYPTION_MODULUS {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption coefficient is not canonical.",
        ));
    }
    if coefficient == 0 {
        return Ok(());
    }
    let current_coefficient = coefficients_by_position
        .get(&(row_index, column_index))
        .copied()
        .unwrap_or(0);
    let next_coefficient = (current_coefficient + coefficient) % RECEIVER_ENCRYPTION_MODULUS;
    if next_coefficient == 0 {
        coefficients_by_position.remove(&(row_index, column_index));
    } else {
        coefficients_by_position.insert((row_index, column_index), next_coefficient);
    }

    Ok(())
}

impl StreamedLinearProofStatement for ParsedStructuredReceiverEncryptionStatement {
    fn source_statement_rows(&self) -> usize {
        self.statement_rows
    }

    fn source_statement_columns(&self) -> usize {
        self.statement_columns
    }

    fn target_vector_coefficients(&self) -> &[Vec<u64>] {
        &self.target_vector_coefficients
    }

    // Source-relation soundness check: matrix*witness + target must be the zero polynomial vector
    // (i.e. A*w + t = 0); any nonzero coefficient rejects the witness.
    fn validate_source_relation(
        &self,
        parameter_set: &LinearProofParameterSet,
        source_witness_vector: &PolynomialVector,
    ) -> crate::encoding::CanonicalResult<()> {
        let source_ring =
            PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?;
        if source_witness_vector.ring() != source_ring
            || source_witness_vector.len() != parameter_set.statement_columns
        {
            return Err(invalid_preflight(
                "Structured receiver-encryption witness shape does not match the parameter set.",
            ));
        }
        let mut relation_output = self
            .source_statement_matrix
            .multiply_vector(source_witness_vector)?;
        let target_vector =
            PolynomialVector::new(source_ring, self.target_vector_coefficients.clone())?;
        relation_output.add_assign(&target_vector)?;
        if relation_output
            .entries()
            .iter()
            .any(|polynomial| polynomial.iter().any(|coefficient| *coefficient != 0))
        {
            return Err(invalid_preflight(
                "Structured receiver-encryption source witness does not satisfy A*w + t = 0.",
            ));
        }

        Ok(())
    }

    // Two-stage transcript hash: arithmetic_statement_hash = shake128(canonical-JSON statement),
    // then public_parameters_and_statement_hash = shake128(public_randomness || that). Binds the
    // public randomness to the statement; the canonical field ordering must be byte-exact for
    // cross-implementation agreement.
    fn derive_statement_transcript(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
        public_randomness: &[u8],
    ) -> crate::encoding::CanonicalResult<
        crate::ballot_privacy::linear_proof::statement::LinearStatementTranscript,
    > {
        // 32 bytes is the fixed public-randomness/seed width for the Fiat-Shamir transcript.
        if public_randomness.len() != 32 {
            return Err(invalid_preflight(
                "structured linear statement public randomness must be exactly 32 bytes",
            ));
        }
        let source_polynomial_split_factor =
            source_polynomial_split_factor(parameter_set, proof_encoding)?;
        let transformed_statement_rows = parameter_set
            .statement_rows
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| invalid_preflight("structured transformed row count overflowed"))?;
        let transformed_statement_columns = parameter_set
            .statement_columns
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| invalid_preflight("structured transformed column count overflowed"))?;
        let transcript_payload = json!({
            "domain": "sealed.vote/internal/structured-linear-statement-transcript-v1",
            "statementHash": &self.statement_hash,
            "parameterSet": {
                "profileId": &parameter_set.profile_id,
                "source": &parameter_set.source,
                "relation": &parameter_set.relation,
                "ringDegree": parameter_set.ring_degree,
                "proofSystemRingDegree": parameter_set.proof_system_ring_degree,
                "coefficientModulus": parameter_set.coefficient_modulus,
                "statementRows": parameter_set.statement_rows,
                "statementColumns": parameter_set.statement_columns,
                "witnessL2BoundSquared": parameter_set.witness_l2_bound_squared
            },
            "proofEncoding": {
                "profileId": &proof_encoding.profile_id,
                "ringDegree": proof_encoding.ring_degree,
                "coefficientModulus": proof_encoding.coefficient_modulus,
                "fullSizeCoefficientBitLength": proof_encoding.full_size_coefficient_bit_length,
                "compressedCoefficientBitLength": proof_encoding.compressed_coefficient_bit_length,
                "targetCommitmentVectorLength": proof_encoding.target_commitment_vector_length,
                "hashMaskVectorLength": proof_encoding.hash_mask_vector_length,
                "compressedCommitmentVectorLength": proof_encoding.compressed_commitment_vector_length,
                "challengeCoefficientModulus": proof_encoding.challenge_coefficient_modulus,
                "challengeCoefficientBitLength": proof_encoding.challenge_coefficient_bit_length,
                "hintVectorLength": proof_encoding.hint_vector_length,
                "shortResponseVectorLength": proof_encoding.short_response_vector_length,
                "randomnessResponseVectorLength": proof_encoding.randomness_response_vector_length,
                "euclideanResponseVectorLength": proof_encoding.euclidean_response_vector_length,
                "infinityResponseVectorLength": proof_encoding.infinity_response_vector_length,
                "shortResponseLog2StandardDeviation": proof_encoding.short_response_log2_standard_deviation,
                "randomnessResponseLog2StandardDeviation": proof_encoding.randomness_response_log2_standard_deviation,
                "euclideanResponseLog2StandardDeviation": proof_encoding.euclidean_response_log2_standard_deviation,
                "infinityResponseLog2StandardDeviation": proof_encoding.infinity_response_log2_standard_deviation,
                "source": &proof_encoding.source
            },
            "matrixCoefficientRepresentation": matrix_coefficient_representation,
            "targetCoefficientRepresentation": target_coefficient_representation,
            "transformedStatementRows": transformed_statement_rows,
            "transformedStatementColumns": transformed_statement_columns,
            "transformedTargetVectorLength": transformed_statement_rows
        });
        let encoded_statement = canonical_json(&transcript_payload)?.into_bytes();
        let arithmetic_statement_hash = shake128_32(&[&encoded_statement]);
        let public_parameters_and_statement_hash =
            shake128_32(&[public_randomness, &arithmetic_statement_hash]);

        Ok(
            crate::ballot_privacy::linear_proof::statement::LinearStatementTranscript {
                transformed_statement_matrix_rows: transformed_statement_rows,
                transformed_statement_matrix_columns: transformed_statement_columns,
                transformed_target_vector_length: transformed_statement_rows,
                encoded_statement_bytes: encoded_statement.len(),
                arithmetic_statement_hash,
                arithmetic_statement_hash_hex: to_hex(&arithmetic_statement_hash),
                public_parameters_and_statement_hash,
                public_parameters_and_statement_hash_hex: to_hex(
                    &public_parameters_and_statement_hash,
                ),
            },
        )
    }

    fn transformed_target_vector(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    ) -> crate::encoding::CanonicalResult<PolynomialVector> {
        let transformed_target_vector = transform_target_vector_to_proof_ring(
            &self.target_vector_coefficients,
            parameter_set,
            proof_encoding,
            target_coefficient_representation,
        )?;

        PolynomialVector::new(
            PolynomialRing::new(
                proof_encoding.ring_degree,
                proof_encoding.coefficient_modulus,
            )?,
            transformed_target_vector,
        )
    }

    fn transformed_relation_output(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        transformed_relation_witness: &PolynomialVector,
        transformed_target_vector: &PolynomialVector,
    ) -> crate::encoding::CanonicalResult<PolynomialVector> {
        let proof_ring = PolynomialRing::new(
            proof_encoding.ring_degree,
            proof_encoding.coefficient_modulus,
        )?;
        if transformed_relation_witness.ring() != proof_ring
            || transformed_target_vector.ring() != proof_ring
        {
            return Err(invalid_preflight(
                "Structured receiver-encryption transformed relation uses inconsistent rings.",
            ));
        }

        let source_polynomial_split_factor =
            source_polynomial_split_factor(parameter_set, proof_encoding)?;
        let transformed_columns = parameter_set
            .statement_columns
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| invalid_preflight("structured transformed column count overflowed"))?;
        if transformed_relation_witness.len() != transformed_columns {
            return Err(invalid_preflight(
                "Structured receiver-encryption transformed witness length does not match the transformed statement.",
            ));
        }

        let mut relation_output_entries = transformed_target_vector.entries().to_vec();
        for_each_transformed_structured_source_entry(
            self,
            parameter_set,
            proof_encoding,
            matrix_coefficient_representation,
            |transformed_row, transformed_column, transformed_coefficients| {
                proof_ring.mul_negacyclic_accumulate(
                    &mut relation_output_entries[transformed_row],
                    transformed_coefficients,
                    &transformed_relation_witness.entries()[transformed_column],
                )
            },
        )?;

        PolynomialVector::new(proof_ring, relation_output_entries)
    }

    fn build_z4_statement_products(
        &self,
        proof_ring: PolynomialRing,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        shifted_rotation_polynomial_matrix: &[Vec<Vec<u64>>],
    ) -> crate::encoding::CanonicalResult<Vec<Vec<Vec<u64>>>> {
        build_z4_statement_products_from_structured_source_entries(
            self,
            proof_ring,
            parameter_set,
            proof_encoding,
            matrix_coefficient_representation,
            shifted_rotation_polynomial_matrix,
        )
    }
}

fn build_z4_statement_products_from_structured_source_entries(
    statement: &ParsedStructuredReceiverEncryptionStatement,
    proof_ring: PolynomialRing,
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    shifted_rotation_polynomial_matrix: &[Vec<Vec<u64>>],
) -> crate::encoding::CanonicalResult<Vec<Vec<Vec<u64>>>> {
    parameter_set.validate()?;
    proof_encoding.validate()?;
    if proof_ring.degree() != proof_encoding.ring_degree
        || proof_ring.modulus() != proof_encoding.coefficient_modulus
    {
        return Err(invalid_preflight(
            "Structured receiver-encryption proof ring does not match the proof encoding.",
        ));
    }
    if statement.source_statement_matrix.rows() != parameter_set.statement_rows
        || statement.source_statement_matrix.columns() != parameter_set.statement_columns
    {
        return Err(invalid_preflight(
            "Structured receiver-encryption source statement matrix shape does not match the parameter set.",
        ));
    }
    if statement.source_statement_matrix.ring().degree() != parameter_set.ring_degree
        || statement.source_statement_matrix.ring().modulus() != parameter_set.coefficient_modulus
    {
        return Err(invalid_preflight(
            "Structured receiver-encryption source statement matrix ring does not match the parameter set.",
        ));
    }

    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    let transformed_rows = parameter_set
        .statement_rows
        .checked_mul(source_polynomial_split_factor)
        .ok_or_else(|| invalid_preflight("structured z4 product row count overflowed"))?;
    let transformed_columns = parameter_set
        .statement_columns
        .checked_mul(source_polynomial_split_factor)
        .ok_or_else(|| invalid_preflight("structured z4 product column count overflowed"))?;

    if shifted_rotation_polynomial_matrix
        .iter()
        .any(|row| row.len() != transformed_rows)
    {
        return Err(invalid_preflight(
            "Structured receiver-encryption z4 rotation rows do not match the transformed statement rows.",
        ));
    }

    let mut output_rows = vec![
        vec![vec![0_u64; proof_ring.degree()]; transformed_columns];
        shifted_rotation_polynomial_matrix.len()
    ];
    for_each_transformed_structured_source_entry(
        statement,
        parameter_set,
        proof_encoding,
        matrix_coefficient_representation,
        |transformed_row, transformed_column, transformed_coefficients| {
            for (output_row, shifted_rotation_row) in output_rows
                .iter_mut()
                .zip(shifted_rotation_polynomial_matrix)
            {
                proof_ring.mul_negacyclic_accumulate(
                    &mut output_row[transformed_column],
                    &shifted_rotation_row[transformed_row],
                    transformed_coefficients,
                )?;
            }

            Ok(())
        },
    )?;

    Ok(output_rows)
}

// Negacyclic block-Toeplitz lift: each source entry expands into a split_factor x split_factor
// block. split_index = output_row_offset - output_column_offset selects which split polynomial;
// negative (wrapped) indices use the negacyclically rotated split (X^n = -1).
fn for_each_transformed_structured_source_entry(
    statement: &ParsedStructuredReceiverEncryptionStatement,
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    mut visit: impl FnMut(usize, usize, &[u64]) -> crate::encoding::CanonicalResult<()>,
) -> crate::encoding::CanonicalResult<()> {
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    let source_modulus_inverse = source_modulus_inverse_mod_proof_modulus(
        parameter_set.coefficient_modulus,
        proof_encoding.coefficient_modulus,
    )?;
    for source_entry in statement.source_statement_matrix.entries() {
        let split_polynomials =
            split_source_polynomial_into_proof_ring_with_coefficient_representation(
                source_entry.coefficients(),
                parameter_set.coefficient_modulus,
                source_polynomial_split_factor,
                matrix_coefficient_representation,
            )?;
        let rotated_split_polynomials = split_polynomials
            .iter()
            .map(|polynomial| rotate_left_negacyclic_signed_polynomial(polynomial))
            .collect::<Vec<_>>();

        for output_row_offset in 0..source_polynomial_split_factor {
            for output_column_offset in 0..source_polynomial_split_factor {
                let split_index = output_row_offset as isize - output_column_offset as isize;
                let signed_polynomial = if split_index >= 0 {
                    &split_polynomials[usize::try_from(split_index)
                        .map_err(|_| invalid_preflight("structured split index overflowed"))?]
                } else {
                    &rotated_split_polynomials[usize::try_from(
                        source_polynomial_split_factor as isize + split_index,
                    )
                    .map_err(|_| invalid_preflight("structured rotated split index overflowed"))?]
                };
                let transformed_coefficients = scale_signed_polynomial_by_precomputed_inverse(
                    signed_polynomial,
                    source_modulus_inverse,
                    proof_encoding.coefficient_modulus,
                )?;
                if transformed_coefficients
                    .iter()
                    .all(|coefficient| *coefficient == 0)
                {
                    continue;
                }
                let transformed_row = source_entry
                    .row_index()
                    .checked_mul(source_polynomial_split_factor)
                    .and_then(|row| row.checked_add(output_row_offset))
                    .ok_or_else(|| invalid_preflight("structured transformed row overflowed"))?;
                let transformed_column = source_entry
                    .column_index()
                    .checked_mul(source_polynomial_split_factor)
                    .and_then(|column| column.checked_add(output_column_offset))
                    .ok_or_else(|| invalid_preflight("structured transformed column overflowed"))?;

                visit(
                    transformed_row,
                    transformed_column,
                    &transformed_coefficients,
                )?;
            }
        }
    }

    Ok(())
}

// Rescales coefficients from the source modulus into the proof modulus by multiplying through the
// precomputed source-modulus inverse and reducing mod the proof modulus.
fn scale_signed_polynomial_by_precomputed_inverse(
    signed_polynomial: &[i128],
    source_modulus_inverse: i128,
    proof_modulus: u64,
) -> crate::encoding::CanonicalResult<Vec<u64>> {
    signed_polynomial
        .iter()
        .map(|coefficient| {
            let scaled = coefficient
                .checked_mul(source_modulus_inverse)
                .ok_or_else(|| {
                    invalid_preflight("structured linear statement coefficient scaling overflowed")
                })?;
            let proof_modulus = i128::from(proof_modulus);
            let mut reduced = scaled % proof_modulus;
            if reduced < 0 {
                reduced += proof_modulus;
            }

            u64::try_from(reduced).map_err(|_| {
                invalid_preflight("structured linear statement coefficient does not fit in u64")
            })
        })
        .collect()
}
