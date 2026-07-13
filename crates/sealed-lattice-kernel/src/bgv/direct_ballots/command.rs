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

    let mut ballot_validity_proofs = Vec::with_capacity(encrypted_ballots.len());
    for (ballot_index, encrypted_ballot) in encrypted_ballots.iter().enumerate() {
        let proof_randomness_hex =
            proof_mask_randomness.ballot_proof_randomness_hex(ballot_index)?;
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
        verify_direct_ballot_relation_proof(
            setup_package,
            &evaluator_key,
            encrypted_ballot,
            &proof_generation.proof_bytes,
        )?;
        ballot_validity_proofs.push(json!({
            "statementHash": proof_generation.statement_hash_hex,
            "proofBytesHash": proof_transport.proof_bytes_hash,
            "proofTransport": {
                "chunkHashes": proof_transport.chunk_hashes,
                "chunkMerkleRoot": proof_transport.chunk_merkle_root,
                "publicTransportHash": proof_transport.public_transport_hash,
            }
        }));
    }
    let aggregation_result = verify_direct_ballot_aggregation(&encrypted_ballots)?;
    let evaluator_replay = match optional_direct_ballot_top_count_request(request)? {
        Some(top_count_request) => {
            let evaluations = run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
                DirectBallotPackedBatchedPairEvaluatorInput {
                    setup_package,
                    evaluator_key: &evaluator_key,
                    aggregate_ciphertext: &aggregation_result.aggregate_ciphertext,
                    ballot_count: encrypted_ballots.len(),
                    top_counts: &top_count_request.top_counts,
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
        None => Value::Null,
    };

    let encrypted_ballot_hashes = encrypted_ballots
        .iter()
        .map(|ballot| ballot.encrypted_ballot_hash.clone())
        .collect::<Vec<_>>();
    let ciphertext_roots = encrypted_ballots
        .iter()
        .map(|ballot| ballot.ciphertext_root.clone())
        .collect::<Vec<_>>();

    Ok(json!({
        "encryptedBallots": {
            "encryptedBallotHashes": encrypted_ballot_hashes,
            "ciphertextRoots": ciphertext_roots
        },
        "ballotValidityProofs": ballot_validity_proofs,
        "aggregation": {
            "aggregateCiphertextRoot": aggregation_result.aggregate_ciphertext_root
        },
        "evaluatorReplay": evaluator_replay
    }))
}
