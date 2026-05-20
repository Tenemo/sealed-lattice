use super::*;
#[cfg(test)]
use crate::ballot_privacy::receiver_polynomial_helpers::{
    negate_receiver_coefficient, parse_receiver_column_vector_with_max_len,
};

pub(crate) fn parse_structured_share_commitment_statement(
    structured_statement: &Value,
) -> Result<ParsedSparseComponentProofStatement, ComponentProofBackendError> {
    if string_field(structured_statement, "objectType")
        != Some("BallotProofStructuredShareCommitmentProofStatement")
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement must use the structured public statement object.",
        ));
    }
    if string_field(structured_statement, "proofStatementFormat")
        != Some(STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement format is invalid.",
        ));
    }
    if string_field(structured_statement, "componentId") != Some("share-commitment-component") {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement is bound to the wrong component.",
        ));
    }
    if u64_object_field(structured_statement, "objectVersion") != Some(1) {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement objectVersion must be 1.",
        ));
    }
    let source_ring_degree = usize_object_field(structured_statement, "sourceRingDegree")
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment proof statement is missing sourceRingDegree.",
            )
        })?;
    if source_ring_degree != SHARE_COMMITMENT_MODULE_DEGREE && source_ring_degree != 64 {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement sourceRingDegree is not supported.",
        ));
    }
    if usize_object_field(structured_statement, "proofSystemRingDegree") != Some(64) {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement proofSystemRingDegree is not supported.",
        ));
    }
    if u64_object_field(structured_statement, "coefficientModulus")
        != Some(SHARE_COMMITMENT_MODULUS)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement modulus is not supported.",
        ));
    }
    if derive_ballot_structured_share_commitment_statement_digest(structured_statement).as_deref()
        != string_field(structured_statement, "statementDigest")
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement digest does not match its canonical payload.",
        ));
    }

    let statement_rows =
        usize_object_field(structured_statement, "statementRows").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment proof statement is missing statementRows.",
            )
        })?;
    let statement_columns = usize_object_field(structured_statement, "statementColumns")
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment proof statement is missing statementColumns.",
            )
        })?;
    let share_vector_width = usize_object_field(structured_statement, "shareVectorWidth")
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment proof statement is missing shareVectorWidth.",
            )
        })?;
    if share_vector_width == 0 || share_vector_width > SHARE_COMMITMENT_MODULE_DEGREE {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement shareVectorWidth is not supported.",
        ));
    }
    let share_commitment_profile_digest = string_field(
        structured_statement,
        "shareCommitmentProfileDigest",
    )
    .ok_or_else(|| {
        ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement is missing shareCommitmentProfileDigest.",
        )
    })?;
    if !is_protocol_digest(share_commitment_profile_digest) {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement profile digest is malformed.",
        ));
    }
    let receiver_rows = object_map(structured_statement)
        .and_then(|object| object.get("receiverRows"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment proof statement receiverRows must be an array.",
            )
        })?;
    if receiver_rows.is_empty() {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement must contain receiver rows.",
        ));
    }
    let source_backend_column_indices = object_map(structured_statement)
        .and_then(|object| object.get("sourceBackendColumnIndices"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment proof statement sourceBackendColumnIndices must be an array.",
            )
        })?;
    if source_backend_column_indices.len() != statement_columns {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment proof statement sourceBackendColumnIndices length does not match statementColumns.",
        ));
    }
    let mut previous_backend_column_index = None;
    for column_index in source_backend_column_indices {
        let column_index = integer_value(column_index).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment source column index is not canonical.",
            )
        })?;
        if previous_backend_column_index.is_some_and(|previous| column_index <= previous) {
            return Err(ComponentProofBackendError::invalid(
                "Structured share-commitment source column indices must be strictly increasing.",
            ));
        }
        previous_backend_column_index = Some(column_index);
    }

    let expected_columns = receiver_rows
        .len()
        .checked_mul(share_vector_width + SHARE_COMMITMENT_OPENING_DIMENSION)
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment statement column count overflowed.",
            )
        })?;
    let row_split_factor = SHARE_COMMITMENT_MODULE_DEGREE
        .checked_div(source_ring_degree)
        .filter(|split_factor| {
            *split_factor > 0 && SHARE_COMMITMENT_MODULE_DEGREE.is_multiple_of(source_ring_degree)
        })
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment sourceRingDegree does not divide the module degree.",
            )
        })?;
    let expected_rows = receiver_rows
        .len()
        .checked_mul(SHARE_COMMITMENT_MODULE_RANK)
        .and_then(|row_count| row_count.checked_mul(row_split_factor))
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment statement row count overflowed.",
            )
        })?;
    if statement_columns != expected_columns || statement_rows != expected_rows {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment statement shape does not match receiver rows.",
        ));
    }

    let source_ring =
        PolynomialRing::new(source_ring_degree, SHARE_COMMITMENT_MODULUS).map_err(|error| {
            ComponentProofBackendError::invalid(format!(
                "Structured share-commitment source ring is invalid: {}",
                error.message
            ))
        })?;
    let message_matrix = derive_share_commitment_message_matrix(share_commitment_profile_digest)?;
    let randomness_matrix =
        derive_share_commitment_randomness_matrix(share_commitment_profile_digest)?;
    let mut source_statement_entries = Vec::new();
    let mut target_vector_coefficients = vec![vec![0_u64; source_ring_degree]; statement_rows];
    let mut covered_row_count = 0_usize;

    for (receiver_index, receiver_row) in receiver_rows.iter().enumerate() {
        let receiver_object = object_map(receiver_row).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment receiver row must be an object.",
            )
        })?;
        if string_field(receiver_row, "receiverIdentity").is_none_or(str::is_empty) {
            return Err(ComponentProofBackendError::invalid(
                "Structured share-commitment receiver row identity is missing.",
            ));
        }
        if positive_roster_position(receiver_row, "receiverRosterPosition").is_none() {
            return Err(ComponentProofBackendError::invalid(
                "Structured share-commitment receiver row roster position is invalid.",
            ));
        }
        let row_offset_within_statement =
            usize_object_field(receiver_row, "rowOffsetWithinStatement").ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured share-commitment receiver row is missing rowOffsetWithinStatement.",
                )
            })?;
        let row_count = usize_object_field(receiver_row, "rowCount").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment receiver row is missing rowCount.",
            )
        })?;
        let expected_receiver_row_count = SHARE_COMMITMENT_MODULE_RANK
            .checked_mul(row_split_factor)
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured share-commitment receiver row count overflowed.",
                )
            })?;
        if row_count != expected_receiver_row_count
            || row_offset_within_statement != receiver_index * expected_receiver_row_count
        {
            return Err(ComponentProofBackendError::invalid(
                "Structured share-commitment receiver row offsets are not canonical.",
            ));
        }
        covered_row_count = covered_row_count.checked_add(row_count).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured share-commitment covered row count overflowed.",
            )
        })?;
        let commitment_polynomial_vector = parse_share_commitment_polynomial_vector(
            receiver_object.get("commitmentPolynomialVector").ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured share-commitment receiver row is missing commitmentPolynomialVector.",
                )
            })?,
            "Structured share-commitment commitment polynomial vector",
        )?;
        let receiver_column_offset = receiver_index
            .checked_mul(share_vector_width + SHARE_COMMITMENT_OPENING_DIMENSION)
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured share-commitment receiver column offset overflowed.",
                )
            })?;

        for module_row_index in 0..SHARE_COMMITMENT_MODULE_RANK {
            let split_target_polynomials = split_share_commitment_polynomial(
                &negate_share_commitment_polynomial(
                    &commitment_polynomial_vector[module_row_index],
                ),
                source_ring_degree,
            )?;
            for (split_index, split_target_polynomial) in
                split_target_polynomials.iter().enumerate()
            {
                let row_index =
                    row_offset_within_statement + module_row_index * row_split_factor + split_index;
                target_vector_coefficients[row_index] = split_target_polynomial.clone();
            }
            for share_coordinate_index in 0..share_vector_width {
                let split_message_polynomials = split_share_commitment_polynomial(
                    &share_commitment_message_entry_polynomial(
                        &message_matrix[module_row_index],
                        share_coordinate_index,
                    ),
                    source_ring_degree,
                )?;
                for (split_index, split_message_polynomial) in
                    split_message_polynomials.iter().enumerate()
                {
                    let row_index = row_offset_within_statement
                        + module_row_index * row_split_factor
                        + split_index;
                    push_share_commitment_sparse_entry(
                        &mut source_statement_entries,
                        row_index,
                        receiver_column_offset + share_coordinate_index,
                        split_message_polynomial.clone(),
                    );
                }
            }
            for opening_coordinate_index in 0..SHARE_COMMITMENT_OPENING_DIMENSION {
                let split_randomness_polynomials = split_share_commitment_polynomial(
                    &randomness_matrix[module_row_index][opening_coordinate_index],
                    source_ring_degree,
                )?;
                for (split_index, split_randomness_polynomial) in
                    split_randomness_polynomials.iter().enumerate()
                {
                    let row_index = row_offset_within_statement
                        + module_row_index * row_split_factor
                        + split_index;
                    push_share_commitment_sparse_entry(
                        &mut source_statement_entries,
                        row_index,
                        receiver_column_offset + share_vector_width + opening_coordinate_index,
                        split_randomness_polynomial.clone(),
                    );
                }
            }
        }
    }
    if covered_row_count != statement_rows {
        return Err(ComponentProofBackendError::invalid(
            "Structured share-commitment receiver rows do not cover the statement row count.",
        ));
    }
    source_statement_entries.sort_by_key(|entry| (entry.row_index(), entry.column_index()));
    let source_statement_matrix = SparsePolynomialMatrix::new(
        source_ring,
        statement_rows,
        statement_columns,
        source_statement_entries,
    )
    .map_err(|error| {
        ComponentProofBackendError::invalid(format!(
            "Structured share-commitment sparse statement matrix is invalid: {}",
            error.message
        ))
    })?;

    Ok(ParsedSparseComponentProofStatement {
        source_statement_matrix,
        target_vector_coefficients,
    })
}

#[cfg(test)]
pub(crate) fn structured_receiver_encryption_statement_as_sparse(
    structured_statement: &Value,
) -> Result<ParsedSparseComponentProofStatement, ComponentProofBackendError> {
    if string_field(structured_statement, "objectType")
        != Some("BallotProofStructuredReceiverEncryptionProofStatement")
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement must use the structured public statement object.",
        ));
    }
    if string_field(structured_statement, "proofStatementFormat")
        != Some(STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement format is invalid.",
        ));
    }
    if string_field(structured_statement, "componentId") != Some("receiver-encryption-component") {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement is bound to the wrong component.",
        ));
    }
    if u64_object_field(structured_statement, "objectVersion") != Some(1) {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement objectVersion must be 1.",
        ));
    }
    if usize_object_field(structured_statement, "sourceRingDegree")
        != Some(RECEIVER_ENCRYPTION_MODULE_DEGREE as usize)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement sourceRingDegree is not supported.",
        ));
    }
    if u64_object_field(structured_statement, "coefficientModulus")
        != Some(RECEIVER_ENCRYPTION_MODULUS)
    {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement modulus is not supported.",
        ));
    }
    let statement_rows =
        usize_object_field(structured_statement, "statementRows").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption proof statement is missing statementRows.",
            )
        })?;
    let statement_columns = usize_object_field(structured_statement, "statementColumns")
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption proof statement is missing statementColumns.",
            )
        })?;
    let receiver_encryption_profile_digest = string_field(
        structured_statement,
        "receiverEncryptionProfileDigest",
    )
    .ok_or_else(|| {
        ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement is missing receiverEncryptionProfileDigest.",
        )
    })?;
    let receiver_rows = object_map(structured_statement)
        .and_then(|object| object.get("receiverRows"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption proof statement receiverRows must be an array.",
            )
        })?;
    if receiver_rows.is_empty() {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption proof statement must contain receiver rows.",
        ));
    }

    let source_ring = PolynomialRing::new(
        RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
        RECEIVER_ENCRYPTION_MODULUS,
    )
    .map_err(|error| {
        ComponentProofBackendError::invalid(format!(
            "Structured receiver-encryption source ring is invalid: {}",
            error.message
        ))
    })?;
    let mut matrix_coefficients_by_position: BTreeMap<(usize, usize), u64> = BTreeMap::new();
    let mut target_vector_coefficients =
        vec![vec![0_u64; RECEIVER_ENCRYPTION_MODULE_DEGREE as usize]; statement_rows];
    let mut covered_row_count = 0_usize;

    for receiver_row in receiver_rows {
        let receiver_object = object_map(receiver_row).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver row must be an object.",
            )
        })?;
        let row_offset_within_statement = usize_object_field(
            receiver_row,
            "rowOffsetWithinStatement",
        )
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver row is missing rowOffsetWithinStatement.",
            )
        })?;
        let row_count = usize_object_field(receiver_row, "rowCount").ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver row is missing rowCount.",
            )
        })?;
        let ciphertext_chunks = receiver_object
            .get("ciphertextChunks")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption receiver row ciphertextChunks must be an array.",
                )
            })?;
        let expected_row_count = ciphertext_chunks
            .len()
            .checked_mul(
                (RECEIVER_ENCRYPTION_MODULE_RANK as usize + 1)
                    .checked_mul(RECEIVER_ENCRYPTION_MODULE_DEGREE as usize)
                    .ok_or_else(|| {
                        ComponentProofBackendError::invalid(
                            "Structured receiver-encryption row count overflowed.",
                        )
                    })?,
            )
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption row count overflowed.",
                )
            })?;
        if row_count != expected_row_count {
            return Err(ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver row count does not match ciphertext chunks.",
            ));
        }
        if row_offset_within_statement
            .checked_add(row_count)
            .is_none_or(|exclusive_end| exclusive_end > statement_rows)
        {
            return Err(ComponentProofBackendError::invalid(
                "Structured receiver-encryption receiver rows exceed the statement shape.",
            ));
        }
        covered_row_count = covered_row_count.checked_add(row_count).ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption covered row count overflowed.",
            )
        })?;

        let public_matrix_seed_digest = string_field(receiver_row, "publicMatrixSeedDigest")
            .ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption receiver row is missing publicMatrixSeedDigest.",
                )
            })?;
        let public_key_vector = parse_receiver_polynomial_vector(
            receiver_object.get("publicKeyVector").ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption receiver row is missing publicKeyVector.",
                )
            })?,
            "Structured receiver-encryption public key vector",
        )?;
        let public_matrix = derive_receiver_encryption_public_matrix(
            receiver_encryption_profile_digest,
            public_matrix_seed_digest,
        )
        .map_err(|error| {
            ComponentProofBackendError::invalid(format!(
                "Structured receiver-encryption public matrix could not be derived: {error}"
            ))
        })?;

        for (chunk_position, ciphertext_chunk) in ciphertext_chunks.iter().enumerate() {
            let chunk_object = object_map(ciphertext_chunk).ok_or_else(|| {
                ComponentProofBackendError::invalid(
                    "Structured receiver-encryption ciphertext chunk must be an object.",
                )
            })?;
            let chunk_index =
                usize_object_field(ciphertext_chunk, "chunkIndex").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing chunkIndex.",
                    )
                })?;
            if chunk_index != chunk_position {
                return Err(ComponentProofBackendError::invalid(
                    "Structured receiver-encryption ciphertext chunks must be in canonical order.",
                ));
            }
            let first_ciphertext_vector = parse_receiver_polynomial_vector(
                chunk_object.get("firstCiphertextVector").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing firstCiphertextVector.",
                    )
                })?,
                "Structured receiver-encryption first ciphertext vector",
            )?;
            let second_ciphertext_polynomial = parse_receiver_polynomial(
                chunk_object.get("secondCiphertextPolynomial").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing secondCiphertextPolynomial.",
                    )
                })?,
                "Structured receiver-encryption second ciphertext polynomial",
            )?;
            let randomness_column_indices = parse_receiver_column_matrix(
                chunk_object.get("randomnessColumnIndices").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing randomnessColumnIndices.",
                    )
                })?,
                statement_columns,
                "Structured receiver-encryption randomness column indices",
            )?;
            let first_noise_column_indices = parse_receiver_column_matrix(
                chunk_object.get("firstNoiseColumnIndices").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing firstNoiseColumnIndices.",
                    )
                })?,
                statement_columns,
                "Structured receiver-encryption first-noise column indices",
            )?;
            let second_noise_column_indices = parse_receiver_column_vector(
                chunk_object.get("secondNoiseColumnIndices").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing secondNoiseColumnIndices.",
                    )
                })?,
                RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
                statement_columns,
                "Structured receiver-encryption second-noise column indices",
            )?;
            let plaintext_bit_column_indices = parse_receiver_column_vector_with_max_len(
                chunk_object.get("plaintextBitColumnIndices").ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing plaintextBitColumnIndices.",
                    )
                })?,
                RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
                statement_columns,
                "Structured receiver-encryption plaintext-bit column indices",
            )?;
            let chunk_row_offset = row_offset_within_statement
                .checked_add(
                    chunk_index
                        .checked_mul(
                            (RECEIVER_ENCRYPTION_MODULE_RANK as usize + 1)
                                * RECEIVER_ENCRYPTION_MODULE_DEGREE as usize,
                        )
                        .ok_or_else(|| {
                            ComponentProofBackendError::invalid(
                                "Structured receiver-encryption chunk row offset overflowed.",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption chunk row offset overflowed.",
                    )
                })?;

            for ciphertext_vector_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
                for output_coefficient_index in 0..RECEIVER_ENCRYPTION_MODULE_DEGREE as usize {
                    let row_index = chunk_row_offset
                        + ciphertext_vector_index * RECEIVER_ENCRYPTION_MODULE_DEGREE as usize
                        + output_coefficient_index;
                    target_vector_coefficients[row_index][0] = negate_receiver_coefficient(
                        first_ciphertext_vector[ciphertext_vector_index][output_coefficient_index],
                    );
                    for randomness_vector_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
                        for randomness_coefficient_index in
                            0..RECEIVER_ENCRYPTION_MODULE_DEGREE as usize
                        {
                            let coefficient = negacyclic_receiver_coefficient(
                                &public_matrix[randomness_vector_index][ciphertext_vector_index],
                                output_coefficient_index,
                                randomness_coefficient_index,
                            );
                            add_structured_constant_entry(
                                &mut matrix_coefficients_by_position,
                                row_index,
                                randomness_column_indices[randomness_vector_index]
                                    [randomness_coefficient_index],
                                coefficient,
                            )?;
                        }
                    }
                    add_structured_constant_entry(
                        &mut matrix_coefficients_by_position,
                        row_index,
                        first_noise_column_indices[ciphertext_vector_index]
                            [output_coefficient_index],
                        1,
                    )?;
                }
            }

            let second_ciphertext_row_offset = chunk_row_offset
                + RECEIVER_ENCRYPTION_MODULE_RANK as usize
                    * RECEIVER_ENCRYPTION_MODULE_DEGREE as usize;
            for output_coefficient_index in 0..RECEIVER_ENCRYPTION_MODULE_DEGREE as usize {
                let row_index = second_ciphertext_row_offset + output_coefficient_index;
                target_vector_coefficients[row_index][0] = negate_receiver_coefficient(
                    second_ciphertext_polynomial[output_coefficient_index],
                );
                for randomness_vector_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
                    for randomness_coefficient_index in
                        0..RECEIVER_ENCRYPTION_MODULE_DEGREE as usize
                    {
                        let coefficient = negacyclic_receiver_coefficient(
                            &public_key_vector[randomness_vector_index],
                            output_coefficient_index,
                            randomness_coefficient_index,
                        );
                        add_structured_constant_entry(
                            &mut matrix_coefficients_by_position,
                            row_index,
                            randomness_column_indices[randomness_vector_index]
                                [randomness_coefficient_index],
                            coefficient,
                        )?;
                    }
                }
                add_structured_constant_entry(
                    &mut matrix_coefficients_by_position,
                    row_index,
                    second_noise_column_indices[output_coefficient_index],
                    1,
                )?;
                if let Some(plaintext_column_index) =
                    plaintext_bit_column_indices.get(output_coefficient_index)
                {
                    add_structured_constant_entry(
                        &mut matrix_coefficients_by_position,
                        row_index,
                        *plaintext_column_index,
                        RECEIVER_ENCRYPTION_MODULUS / 2,
                    )?;
                }
            }
        }
    }
    if covered_row_count != statement_rows {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption receiver rows do not cover the statement row count.",
        ));
    }

    let sparse_matrix_entries = matrix_coefficients_by_position
        .into_iter()
        .filter_map(|((row_index, column_index), coefficient)| {
            if coefficient == 0 {
                None
            } else {
                let mut coefficients = vec![0_u64; RECEIVER_ENCRYPTION_MODULE_DEGREE as usize];
                coefficients[0] = coefficient;
                Some(SparsePolynomialMatrixEntry::new(
                    row_index,
                    column_index,
                    coefficients,
                ))
            }
        })
        .collect::<Vec<_>>();
    let source_statement_matrix = SparsePolynomialMatrix::new(
        source_ring,
        statement_rows,
        statement_columns,
        sparse_matrix_entries,
    )
    .map_err(|error| {
        ComponentProofBackendError::invalid(format!(
            "Structured receiver-encryption sparse statement matrix is invalid: {}",
            error.message
        ))
    })?;

    Ok(ParsedSparseComponentProofStatement {
        source_statement_matrix,
        target_vector_coefficients,
    })
}
