use super::*;

pub(crate) fn run_direct_encrypted_ballot(request: &Value) -> CanonicalResult<Value> {
    let setup_package = required_object_field(request, "setupPackage")?;
    let private_setup_seed =
        required_string_path(request, &["setupPrivateWitness", "setupSeed"])?.to_string();

    let (ballots, ballot_encryption_randomness) = read_ballots(request)?;
    if ballots.len() > MAXIMUM_PROTOTYPE_BALLOTS {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot command currently supports at most twenty ballots",
        ));
    }
    validate_direct_ballot_batch_order(&ballots)?;
    for ballot in &ballots {
        validate_direct_ballot_input(ballot)?;
    }
    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    validate_private_setup_seed_from_passive_setup_package(setup_package, &private_setup_seed)?;
    let proof_mask_randomness = read_direct_ballot_proof_mask_randomness(request, ballots.len())?;
    validate_disjoint_direct_ballot_randomness(
        &ballot_encryption_randomness.encryption_seed_hexes,
        &proof_mask_randomness.ballot_proof_randomness_hexes,
    )?;

    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, &private_setup_seed)?;
    let mut encrypted_ballots = Vec::with_capacity(ballots.len());
    for ballot in ballots {
        let encrypted_ballot = encrypt_direct_ballot(setup_package, &evaluator_key, ballot)?;
        validate_direct_ballot_preflight(&evaluator_key, &encrypted_ballot)?;
        encrypted_ballots.push(encrypted_ballot);
    }

    let mut proof_summaries = Vec::with_capacity(encrypted_ballots.len());
    let mut total_proving_time_milliseconds = DirectBallotTimingTotal::new();
    let mut total_verification_time_milliseconds = DirectBallotTimingTotal::new();
    for (ballot_index, encrypted_ballot) in encrypted_ballots.iter().enumerate() {
        let proof_randomness_hex =
            proof_mask_randomness.ballot_proof_randomness_hex(ballot_index)?;
        let proof_generation_started = DirectBallotTimingStart::now();
        let proof_generation = generate_direct_ballot_relation_proof(
            setup_package,
            &evaluator_key,
            encrypted_ballot,
            proof_randomness_hex,
        )?;
        let proof_transport = transport_direct_ballot_binary_proof(
            setup_package,
            encrypted_ballot,
            &proof_generation.statement_hash_hex,
            &proof_generation.proof_bytes,
            &proof_generation.proof_bytes_hash,
            direct_ballot_relation_proof_bytes_hash,
            "direct ballot relation proof",
        )?;
        total_proving_time_milliseconds.add(proof_generation_started.elapsed_milliseconds());
        let proof_verification_started = DirectBallotTimingStart::now();
        verify_direct_ballot_relation_proof(
            setup_package,
            &evaluator_key,
            encrypted_ballot,
            &proof_transport.proof_bytes,
        )?;
        total_verification_time_milliseconds.add(proof_verification_started.elapsed_milliseconds());
        proof_summaries.push(DirectBallotRelationProofSummary::from_verified_proof(
            proof_generation,
            proof_transport,
        ));
    }
    let first_proof = proof_summaries.first().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct encrypted ballot command requires at least one proof",
        )
    })?;
    let total_proof_bytes = proof_summaries
        .iter()
        .map(|proof_summary| proof_summary.proof_size_bytes)
        .sum::<usize>();
    let aggregation_result = verify_direct_ballot_aggregation(&evaluator_key, &encrypted_ballots)?;
    let public_evaluation_key_material = request.get("publicEvaluationKeyMaterial");
    let evaluator_replay = match optional_direct_ballot_top_count_request(request)? {
        Some(top_count_request) => {
            let evaluations = run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
                DirectBallotPackedBatchedPairEvaluatorInput {
                    setup_package,
                    evaluator_key: &evaluator_key,
                    aggregate_ciphertext: &aggregation_result.aggregate_ciphertext,
                    aggregate_scores: &aggregation_result.aggregate_scores,
                    ballot_count: encrypted_ballots.len(),
                    top_counts: &top_count_request.top_counts,
                    public_evaluation_key_material,
                    target_finality_policy_hash: top_count_request
                        .target_finality_policy_hash
                        .as_deref(),
                },
            )?;
            if top_count_request.report_single_result {
                evaluations
                    .into_iter()
                    .next()
                    .expect("single top-count request produces one evaluator report")
            } else {
                Value::Array(evaluations)
            }
        }
        None => json!(
            "Not run in this command. Supply topCount to attempt the packed batched-pair evaluator route over the direct aggregate."
        ),
    };

    let ciphertext_byte_lengths = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ciphertext_canonical_byte_length)
        .collect::<Vec<_>>();
    let encrypted_ballot_hashes = encrypted_ballots
        .iter()
        .map(|ballot| ballot.encrypted_ballot_hash.clone())
        .collect::<Vec<_>>();
    let ciphertext_roots = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ciphertext_root.clone())
        .collect::<Vec<_>>();

    Ok(json!({
        "operation": OPERATION,
        "parameters": {
            "bgvParametersHash": bgv_parameters_hash()?,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "dataPrimeCount": DATA_PRIMES.len()
        },
        "ballotLayout": {
            "optionCount": OPTION_COUNT,
            "scoreSlots": "slots 0 through 19 hold one scalar score per option",
            "reservedSlots": "all remaining slots are zero before encryption",
            "scoreRange": "scores must be integers from 1 through 10"
        },
        "input": {
            "ballotCount": encrypted_ballots.len()
        },
        "encryptedBallots": {
            "encryptedBallotHashes": encrypted_ballot_hashes,
            "ciphertextRoots": ciphertext_roots,
            "ciphertextCanonicalByteLengths": ciphertext_byte_lengths,
            "ballotEncryptionRandomness": ballot_encryption_randomness.report_value()
        },
        "proofAttempt": {
            "proofEncoding": "internal binary feasibility encoding",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "rnsLimbCount": DATA_PRIMES.len(),
            "responseEncoding": "full BGV-degree signed response polynomials plus direct ballot score scalars",
            "responsePolynomialDegree": POLYNOMIAL_DEGREE,
            "binaryRelationCommitmentBytes": first_proof.relation_commitment_bytes,
            "binarySharedResponseBytes": first_proof.response_bytes,
            "proofCount": proof_summaries.len(),
            "proofSizeBytes": first_proof.proof_size_bytes,
            "totalProofBytes": total_proof_bytes,
            "proofBytesHash": first_proof.proof_bytes_hash,
            "statementHash": first_proof.statement_hash_hex,
            "relationCommitmentHash": first_proof.relation_commitment_hash_hex,
            "challenge": first_proof.challenge.to_string(),
            "proofTransport": {
                "encoding": "binary proof chunks",
                "chunksPerProof": first_proof.proof_chunk_count,
                "chunksForBatch": chunk_count_for_bytes(total_proof_bytes, PROTOTYPE_PROOF_CHUNK_BYTES)?,
                "transportedProofSizeBytes": first_proof.transported_proof_size_bytes,
                "transportedProofBytesHash": first_proof.transported_proof_bytes_hash,
                "firstProofChunkMerkleRoot": first_proof.proof_chunk_merkle_root,
                "firstProofChunkHashes": first_proof.proof_chunk_hashes,
                "firstProofPublicTransportHash": first_proof.public_proof_transport_hash,
                "firstProofStatementHash": first_proof.statement_hash_hex,
                "proofParametersHash": direct_ballot_relation_proof_parameters_hash()?
            },
            "proofMaskRandomness": proof_mask_randomness.report_value(),
            "provingTimeMilliseconds": total_proving_time_milliseconds.report_value(),
            "verificationTimeMilliseconds": total_verification_time_milliseconds.report_value()
        },
        "aggregation": aggregation_result.report,
        "evaluatorReplay": evaluator_replay
    }))
}
