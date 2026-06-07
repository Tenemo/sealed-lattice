use super::*;

pub(crate) fn run_direct_encrypted_ballot(request: &Value) -> CanonicalResult<Value> {
    let setup_package = required_object_field(request, "setupPackage")?;
    let private_setup_seed =
        required_string_path(request, &["setupPrivateWitness", "setupSeed"])?.to_string();

    let (ballots, ballot_encryption_randomness) = read_ballots(request)?;
    if ballots.len() > DIRECT_BALLOT_MAXIMUM_PROTOTYPE_BALLOTS {
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
        let proof_verification = verify_direct_ballot_relation_proof(
            setup_package,
            &evaluator_key,
            encrypted_ballot,
            &proof_transport.proof_bytes,
        )?;
        total_verification_time_milliseconds.add(proof_verification_started.elapsed_milliseconds());
        proof_summaries.push(DirectBallotRelationProofSummary::from_verified_proof(
            proof_generation,
            proof_transport,
            proof_verification,
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
                setup_package,
                &evaluator_key,
                &aggregation_result.aggregate_ciphertext,
                &aggregation_result.aggregate_scores,
                encrypted_ballots.len(),
                &top_count_request.top_counts,
                public_evaluation_key_material,
                top_count_request.target_finality_policy_hash.as_deref(),
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
        "operation": DIRECT_BALLOT_OPERATION,
        "profile": {
            "profileId": PROFILE_ID,
            "profileHash": profile_hash()?,
            "polynomialDegree": POLYNOMIAL_DEGREE,
            "plaintextModulus": PLAINTEXT_MODULUS,
            "dataPrimeCount": DATA_PRIMES.len()
        },
        "ballotLayout": {
            "optionCount": DIRECT_BALLOT_OPTION_COUNT,
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
            "ballotEncryptionRandomness": ballot_encryption_randomness.report_value(),
            "result": "Direct score slots, one-hot witnesses, batch encoding, all data-limb encryption algebra, and reserved zero slots passed private preflight."
        },
        "proofAttempt": {
            "relation": "all BGV data-prime encryption equations for c0=b*u+p*e0+encode(score) and c1=a*u+p*e1, with score-to-encoding carry linkage",
            "coverage": "all RNS limb encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support are checked by one internal binary transcript; claim soundness and zero-knowledge are not accepted for the current proof model",
            "proofEncoding": "internal binary feasibility encoding",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "rnsLimbCount": DATA_PRIMES.len(),
            "responseEncoding": "full BGV-degree signed response polynomials plus direct ballot score scalars",
            "responsePolynomialDegree": POLYNOMIAL_DEGREE,
            "binaryRelationCommitmentBytes": first_proof.relation_commitment_bytes,
            "binarySharedResponseBytes": first_proof.response_bytes,
            "proofCount": proof_summaries.len(),
            "proofSizeBytes": first_proof.proof_size_bytes,
            "verifiedProofSizeBytes": first_proof.verified_proof_size_bytes,
            "totalProofBytes": total_proof_bytes,
            "proofBytesHash": first_proof.proof_bytes_hash,
            "statementHash": first_proof.statement_hash_hex,
            "verifiedStatementHash": first_proof.verified_statement_hash_hex,
            "relationCommitmentHash": first_proof.relation_commitment_hash_hex,
            "verifiedRelationCommitmentHash": first_proof.verified_relation_commitment_hash_hex,
            "challenge": first_proof.challenge.to_string(),
            "verifiedChallenge": first_proof.verified_challenge.to_string(),
            "challengeSoundness": format!("single nominal {}-bit challenge; claim soundness is not accepted because weaker subrelations reduce the challenge modulo smaller rings and the current support-proof model is not accepted", direct_ballot_relation_challenge_bits()),
            "proofAccounting": direct_ballot_relation_proof_accounting(first_proof.proof_size_bytes, total_proof_bytes)?,
            "proofTransport": {
                "encoding": "binary proof chunks",
                "status": "each generated proof is framed into fixed-size binary chunks, chunk-hash checked, root-checked, reassembled, and verified from the transported bytes",
                "retention": "proof chunks and reassembled proof bytes are verified and then dropped; the report keeps hashes, sizes, chunk counts, and chunk Merkle roots only",
                "chunkSizeBytes": DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
                "chunksPerProof": first_proof.proof_chunk_count,
                "chunksForBatch": chunk_count_for_bytes(total_proof_bytes, DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)?,
                "transportedProofSizeBytes": first_proof.transported_proof_size_bytes,
                "transportedProofBytesHash": first_proof.transported_proof_bytes_hash,
                "firstProofChunkMerkleRoot": first_proof.proof_chunk_merkle_root,
                "firstProofChunkHashes": first_proof.proof_chunk_hashes,
                "firstProofPublicTransportHash": first_proof.public_proof_transport_hash,
                "firstProofStatementHash": first_proof.statement_hash_hex,
                "proofProfileHash": direct_ballot_relation_proof_profile_hash()?
            },
            "proofMaskRandomness": proof_mask_randomness.report_value(),
            "relationCommitmentPolynomialCount": first_proof.relation_commitment_polynomial_count,
            "sharedResponsePolynomialCount": first_proof.shared_response_polynomial_count,
            "sharedScoreResponseScalarCount": first_proof.shared_response_scalar_count,
            "responseSharing": "one binary response vector is checked against all 17 RNS limb equations, score-linear constraints, and support constraints; response bytes are not duplicated per limb",
            "timingStatus": direct_ballot_timing_status(),
            "provingTimeMilliseconds": total_proving_time_milliseconds.report_value(),
            "verificationTimeMilliseconds": total_verification_time_milliseconds.report_value(),
            "proofGate": first_proof.proof_gate,
            "generation": "Generated and verified one internal binary proof for the all-limb BGV encryption relation, score-linear constraints, and support constraints. This is internal relation evidence only; the proof model is not claim-bearing until weakest-relation soundness and zero-knowledge support checks are fixed.",
            "fullRnsCoverage": "The proof covers all 17 BGV RNS limbs with one shared randomizer, error, encoding-carry, score, and one-hot response vector.",
            "blocker": "Next missing pieces are accepted weakest-relation soundness accounting, replacement or formal redesign of witness-dependent support commitments, Fiat-Shamir/QROM review, mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, public package proof transport for an accepted proof profile, public accepted randomness API boundaries, target share proof certification, smudging/noise C1-C4 closure, and public target-decryption integration. Runs using development-deterministic-fixture proof masks or ballot-encryption randomness remain fixture evidence only."
        },
        "aggregation": aggregation_result.report,
        "evaluatorReplay": evaluator_replay,
        "decision": "Direct BGV ballot encryption, all-limb private preflight, one widened shared-response internal proof, direct ciphertext aggregation, binary chunk proof transport with public hashes, and requested-top-count encrypted sparse target projection are the active path. They are not claim-bearing because proof soundness is not accepted, current support commitments are not accepted as zero-knowledge, mobile evidence is missing, public accepted proof transport is missing, public accepted randomness boundaries are not finalized, and target share proof/C1-C4/public target-decryption gates are not closed."
    }))
}
