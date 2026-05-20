use super::*;

pub(crate) fn parse_structured_receiver_encryption_statement(
    structured_statement: &Value,
) -> Result<ParsedStructuredReceiverEncryptionStatement, ComponentProofBackendError> {
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
    let statement_digest = string_field(structured_statement, "statementDigest")
        .ok_or_else(|| {
            ComponentProofBackendError::invalid(
                "Structured receiver-encryption proof statement is missing statementDigest.",
            )
        })?
        .to_string();
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
    let mut source_statement_entries = Vec::new();
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
            .checked_mul(RECEIVER_ENCRYPTION_MODULE_RANK as usize + 1)
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
            let randomness_column_indices = parse_receiver_column_vector(
                chunk_object
                    .get("randomnessPolynomialColumnIndices")
                    .ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing randomnessPolynomialColumnIndices.",
                    )
                })?,
                RECEIVER_ENCRYPTION_MODULE_RANK as usize,
                statement_columns,
                "Structured receiver-encryption randomness column indices",
            )?;
            let first_noise_column_indices = parse_receiver_column_vector(
                chunk_object
                    .get("firstNoisePolynomialColumnIndices")
                    .ok_or_else(|| {
                    ComponentProofBackendError::invalid(
                        "Structured receiver-encryption ciphertext chunk is missing firstNoisePolynomialColumnIndices.",
                    )
                })?,
                RECEIVER_ENCRYPTION_MODULE_RANK as usize,
                statement_columns,
                "Structured receiver-encryption first-noise column indices",
            )?;
            let second_noise_column_index = parse_receiver_column_index(
                chunk_object
                    .get("secondNoiseColumnIndex")
                    .ok_or_else(|| {
                        ComponentProofBackendError::invalid(
                            "Structured receiver-encryption ciphertext chunk is missing secondNoiseColumnIndex.",
                        )
                    })?,
                statement_columns,
                "Structured receiver-encryption second-noise column index",
            )?;
            let plaintext_column_index = parse_receiver_column_index(
                chunk_object
                    .get("plaintextPolynomialColumnIndex")
                    .ok_or_else(|| {
                        ComponentProofBackendError::invalid(
                            "Structured receiver-encryption ciphertext chunk is missing plaintextPolynomialColumnIndex.",
                        )
                    })?,
                statement_columns,
                "Structured receiver-encryption plaintext column index",
            )?;
            let chunk_row_offset = row_offset_within_statement
                .checked_add(
                    chunk_index
                        .checked_mul(RECEIVER_ENCRYPTION_MODULE_RANK as usize + 1)
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
                let row_index = chunk_row_offset + ciphertext_vector_index;
                target_vector_coefficients[row_index] =
                    negate_receiver_polynomial(&first_ciphertext_vector[ciphertext_vector_index]);
                for randomness_vector_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
                    push_receiver_sparse_entry(
                        &mut source_statement_entries,
                        row_index,
                        randomness_column_indices[randomness_vector_index],
                        public_matrix[randomness_vector_index][ciphertext_vector_index].clone(),
                    );
                }
                push_receiver_sparse_entry(
                    &mut source_statement_entries,
                    row_index,
                    first_noise_column_indices[ciphertext_vector_index],
                    receiver_constant_polynomial(1),
                );
            }
            let second_ciphertext_row_index =
                chunk_row_offset + RECEIVER_ENCRYPTION_MODULE_RANK as usize;
            target_vector_coefficients[second_ciphertext_row_index] =
                negate_receiver_polynomial(&second_ciphertext_polynomial);
            for randomness_vector_index in 0..RECEIVER_ENCRYPTION_MODULE_RANK as usize {
                push_receiver_sparse_entry(
                    &mut source_statement_entries,
                    second_ciphertext_row_index,
                    randomness_column_indices[randomness_vector_index],
                    public_key_vector[randomness_vector_index].clone(),
                );
            }
            push_receiver_sparse_entry(
                &mut source_statement_entries,
                second_ciphertext_row_index,
                second_noise_column_index,
                receiver_constant_polynomial(1),
            );
            push_receiver_sparse_entry(
                &mut source_statement_entries,
                second_ciphertext_row_index,
                plaintext_column_index,
                receiver_constant_polynomial(RECEIVER_ENCRYPTION_MODULUS / 2),
            );
        }
    }
    if covered_row_count != statement_rows {
        return Err(ComponentProofBackendError::invalid(
            "Structured receiver-encryption receiver rows do not cover the statement row count.",
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
            "Structured receiver-encryption sparse statement matrix is invalid: {}",
            error.message
        ))
    })?;

    Ok(ParsedStructuredReceiverEncryptionStatement {
        statement_digest,
        statement_rows,
        statement_columns,
        source_statement_matrix,
        target_vector_coefficients,
    })
}
