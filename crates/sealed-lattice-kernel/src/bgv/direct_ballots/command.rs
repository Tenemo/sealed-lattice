use super::*;

pub(crate) fn run_direct_encrypted_ballot(request: &Value) -> CanonicalResult<Value> {
    let setup_package = required_object_field(request, "setupPackage")?;
    let private_setup_seed =
        required_string_path(request, &["setupPrivateWitness", "setupSeed"])?.to_string();
    let ballot_input = read_direct_ballot_development_ballot_input(request, setup_package)?;

    validate_passive_setup_package_for_encrypted_evaluation(setup_package)?;
    validate_private_setup_seed_from_passive_setup_package(setup_package, &private_setup_seed)?;
    let package_input = attach_direct_ballot_proof_mask_randomness(request, ballot_input)?;
    let package_run = generate_direct_ballot_public_packages_from_input(package_input)?;
    let evaluator_key =
        development_evaluator_key_from_passive_setup_package(setup_package, &private_setup_seed)?;
    for encrypted_ballot in &package_run.encrypted_ballots {
        validate_direct_ballot_development_preflight(&evaluator_key, encrypted_ballot)?;
    }

    let first_proof = package_run.first_proof()?;
    let total_proof_bytes = package_run.total_proof_bytes();
    let aggregation_result =
        verify_direct_ballot_aggregation(&evaluator_key, &package_run.encrypted_ballots)?;
    let public_evaluation_key_material = request.get("publicEvaluationKeyMaterial");
    let evaluator_replay = match optional_direct_ballot_top_count_request(request)? {
        Some(top_count_request) => {
            let evaluations = run_direct_ballot_packed_batched_pair_evaluator_for_top_counts(
                DirectBallotPackedBatchedPairEvaluatorInput {
                    setup_package,
                    evaluator_key: &evaluator_key,
                    aggregate_ciphertext: &aggregation_result.aggregate_ciphertext,
                    aggregate_scores: &aggregation_result.aggregate_scores,
                    ballot_count: package_run.encrypted_ballots.len(),
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

    let ciphertext_byte_lengths = package_run.ciphertext_byte_lengths();
    let encrypted_ballot_hashes = package_run.encrypted_ballot_hashes();
    let ciphertext_roots = package_run.ciphertext_roots();

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
            "ballotCount": package_run.encrypted_ballots.len()
        },
        "encryptedBallots": {
            "encryptedBallotHashes": encrypted_ballot_hashes,
            "ciphertextRoots": ciphertext_roots,
            "ciphertextCanonicalByteLengths": ciphertext_byte_lengths,
            "ballotEncryptionRandomness": package_run.ballot_encryption_randomness.report_value(),
            "result": "Direct score slots, one-hot witnesses, batch encoding, reserved zero slots, and all data-limb encryption algebra passed public-key preflight; development decrypt preflight also matched submitted score slots."
        },
        "proofAttempt": {
            "relation": "statement-derived projected BGV data-prime encryption rows for c0=b*u+p*e0+encode(score) and c1=a*u+p*e1, with score-to-encoding carry linkage",
            "coverage": "projected BGV rows and projected no-wrap carry rows for every RNS limb component are checked by the projected response transcript; score row sums and score weighted-sum constraints are checked as exact signed integer relations against the full Fiat-Shamir challenge; the appended committed trace proof binds one-hot Booleanity, ternary randomizer support, centered-binomial error support, helper-square consistency, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score row sums, score linkage, projected BGV field rows, cross-prime no-wrap carry linkage, and packed-column shape to salted masked columns; conservative projected-BGV, committed-trace soundness, zero-knowledge budgets, the accepted verifier certificate, accepted randomness boundary, and package verification certificates are recorded",
            "proofEncoding": "internal binary feasibility encoding with appended committed trace proof",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "rnsLimbCount": DATA_PRIMES.len(),
            "responseEncoding": "full BGV-degree signed response polynomials, direct ballot score scalars, one-hot scalars, and projected BGV no-wrap carry scalars",
            "bgvCommitmentEncoding": "statement-derived projected scalar commitments",
            "projectedBgvRelationProjectionsPerLimbComponent": DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
            "responsePolynomialDegree": POLYNOMIAL_DEGREE,
            "binaryRelationCommitmentBytes": first_proof.relation_commitment_bytes,
            "binarySharedResponseBytes": first_proof.response_bytes,
            "proofCount": package_run.proof_summaries.len(),
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
            "challengeSoundness": format!("single nominal {}-bit outer challenge plus independent committed-trace batching; score linkage uses exact signed integer commitments and the full challenge, projected BGV rows record a random-projection budget, committed-trace rows record a conservative soundness budget, mask/opening distributions record zero-knowledge slack, and accepted package creation refuses fixture randomness. This development command remains fixture evidence when fixture-labelled randomness is supplied", direct_ballot_relation_challenge_bits()),
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
                "firstProofChunkManifestRoot": first_proof.proof_chunk_manifest_root,
                "firstProofChunkManifest": first_proof.proof_chunk_manifest,
                "firstEncryptedBallotPackageRoot": first_proof.encrypted_ballot_package_root,
                "firstEncryptedBallotPackage": first_proof.encrypted_ballot_package,
                "firstVoterSignatureSignedRoot": first_proof.voter_signature_signed_root,
                "firstProofStatementHash": first_proof.statement_hash_hex,
                "proofProfileHash": direct_ballot_relation_proof_profile_hash()?,
                "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
                "soundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
                "zeroKnowledgeCertificateHash": direct_ballot_zero_knowledge_certificate_hash()?,
                "verifierCertificateHash": direct_ballot_verifier_certificate_hash()?
            },
            "proofMaskRandomness": package_run.proof_mask_randomness.report_value(),
            "relationCommitmentScalarCount": first_proof.relation_commitment_scalar_count,
            "sharedResponsePolynomialCount": first_proof.shared_response_polynomial_count,
            "sharedResponseScalarCount": first_proof.shared_response_scalar_count,
            "responseSharing": "one binary response vector is checked against statement-derived projected BGV rows, projected no-wrap carry rows, and score-linear constraints; support rows are checked by the appended committed trace proof; response bytes are not duplicated per limb",
            "timingStatus": direct_ballot_timing_status(),
            "provingTimeMilliseconds": package_run.total_proving_time_milliseconds.report_value(),
            "verificationTimeMilliseconds": package_run.total_verification_time_milliseconds.report_value(),
            "proofGate": first_proof.proof_gate,
            "generation": "Generated and verified one binary proof with projected all-limb BGV encryption rows, exact integer score-linear constraints, and an appended committed trace proof for support, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score, projected BGV field, and cross-prime no-wrap carry rows. Conservative soundness, zero-knowledge accounting, the accepted verifier certificate, and the accepted randomness boundary are recorded for this proof profile; this development command remains fixture evidence when fixture-labelled randomness is supplied.",
            "projectedRnsCoverage": "The proof derives projected rows for all 17 BGV RNS limbs with one shared randomizer, error, encoding-carry, score, and one-hot response vector, while score linkage uses exact integer commitments outside the plaintext modulus.",
            "blocker": "Next missing pieces are mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, target share proof certification, smudging/noise C1-C4 closure, and public target-decryption integration. Runs using development-deterministic-fixture proof masks or ballot-encryption randomness remain fixture evidence only."
        },
        "aggregation": aggregation_result.report,
        "evaluatorReplay": evaluator_replay,
        "decision": "Direct BGV ballot encryption, all-limb public-key preflight, development decrypt preflight, one widened shared-response proof with exact integer score linkage, recorded projected-BGV soundness, committed-trace soundness, zero-knowledge budgets, accepted verifier certification, accepted randomness boundaries, direct ciphertext aggregation, package-level binary proof chunk manifests, and requested-top-count encrypted sparse target projection are the active path. They are not claim-bearing because mobile evidence, target share proof/C1-C4, and public target-decryption gates are not closed, and this development command can still run with fixture-labelled randomness."
    }))
}

pub(crate) fn create_direct_encrypted_ballot_packages(request: &Value) -> CanonicalResult<Value> {
    reject_public_package_private_fields(request)?;
    let package_run = generate_direct_ballot_public_packages(request)?;

    direct_ballot_public_package_report(&package_run)
}

struct DirectBallotPublicPackageRun {
    encrypted_ballots: Vec<DirectEncryptedBallot>,
    proof_summaries: Vec<DirectBallotRelationProofSummary>,
    ballot_encryption_randomness: DirectBallotEncryptionRandomness,
    proof_mask_randomness: DirectBallotProofMaskRandomness,
    accepted_setup_handoff_root: String,
    total_proving_time_milliseconds: DirectBallotTimingTotal,
    total_verification_time_milliseconds: DirectBallotTimingTotal,
}

enum DirectBallotPublicKeyMaterialKind {
    AcceptedPublicKeyMaterial,
    PassiveDevelopmentSetupPackage,
}

struct DirectBallotPublicBallotInput<'a> {
    public_key_material: &'a Value,
    public_key_material_kind: DirectBallotPublicKeyMaterialKind,
    accepted_setup_handoff_root: String,
    ballots: Vec<DirectBallotInput>,
    ballot_encryption_randomness: DirectBallotEncryptionRandomness,
}

struct DirectBallotPublicPackageInput<'a> {
    public_key_material: &'a Value,
    public_key_material_kind: DirectBallotPublicKeyMaterialKind,
    accepted_setup_handoff_root: String,
    ballots: Vec<DirectBallotInput>,
    ballot_encryption_randomness: DirectBallotEncryptionRandomness,
    proof_mask_randomness: DirectBallotProofMaskRandomness,
}

impl DirectBallotPublicPackageRun {
    fn first_proof(&self) -> CanonicalResult<&DirectBallotRelationProofSummary> {
        self.proof_summaries.first().ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct encrypted ballot command requires at least one proof",
            )
        })
    }

    fn total_proof_bytes(&self) -> usize {
        self.proof_summaries
            .iter()
            .map(|proof_summary| proof_summary.proof_size_bytes)
            .sum::<usize>()
    }

    fn ciphertext_byte_lengths(&self) -> Vec<usize> {
        self.encrypted_ballots
            .iter()
            .map(|ballot| ballot.ciphertext_canonical_byte_length)
            .collect::<Vec<_>>()
    }

    fn encrypted_ballot_hashes(&self) -> Vec<String> {
        self.encrypted_ballots
            .iter()
            .map(|ballot| ballot.encrypted_ballot_hash.clone())
            .collect::<Vec<_>>()
    }

    fn ciphertext_roots(&self) -> Vec<String> {
        self.encrypted_ballots
            .iter()
            .map(|ballot| ballot.ciphertext_root.clone())
            .collect::<Vec<_>>()
    }
}

fn generate_direct_ballot_public_packages(
    request: &Value,
) -> CanonicalResult<DirectBallotPublicPackageRun> {
    let package_input = read_direct_ballot_public_package_input(request)?;

    generate_direct_ballot_public_packages_from_input(package_input)
}

fn read_direct_ballot_public_package_input(
    request: &Value,
) -> CanonicalResult<DirectBallotPublicPackageInput<'_>> {
    let ballot_input = read_direct_ballot_public_ballot_input(request)?;

    let package_input = attach_direct_ballot_proof_mask_randomness(request, ballot_input)?;
    validate_accepted_direct_ballot_package_randomness(&package_input)?;

    Ok(package_input)
}

fn read_direct_ballot_public_ballot_input(
    request: &Value,
) -> CanonicalResult<DirectBallotPublicBallotInput<'_>> {
    let accepted_public_key_material = required_object_field(request, "acceptedPublicKeyMaterial")?;
    let accepted_setup_handoff = required_object_field(request, "acceptedSetupHandoff")?;
    let accepted_setup_handoff_root =
        validate_direct_ballot_setup_handoff(accepted_public_key_material, accepted_setup_handoff)?;

    read_direct_ballot_ballot_input(
        request,
        accepted_public_key_material,
        DirectBallotPublicKeyMaterialKind::AcceptedPublicKeyMaterial,
        accepted_setup_handoff_root,
    )
}

fn read_direct_ballot_development_ballot_input<'a>(
    request: &Value,
    setup_package: &'a Value,
) -> CanonicalResult<DirectBallotPublicBallotInput<'a>> {
    read_direct_ballot_ballot_input(
        request,
        setup_package,
        DirectBallotPublicKeyMaterialKind::PassiveDevelopmentSetupPackage,
        "not used by the development direct ballot command".to_string(),
    )
}

fn read_direct_ballot_ballot_input<'a>(
    request: &Value,
    public_key_material: &'a Value,
    public_key_material_kind: DirectBallotPublicKeyMaterialKind,
    accepted_setup_handoff_root: String,
) -> CanonicalResult<DirectBallotPublicBallotInput<'a>> {
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

    Ok(DirectBallotPublicBallotInput {
        public_key_material,
        public_key_material_kind,
        accepted_setup_handoff_root,
        ballots,
        ballot_encryption_randomness,
    })
}

fn attach_direct_ballot_proof_mask_randomness<'a>(
    request: &Value,
    ballot_input: DirectBallotPublicBallotInput<'a>,
) -> CanonicalResult<DirectBallotPublicPackageInput<'a>> {
    let proof_mask_randomness =
        read_direct_ballot_proof_mask_randomness(request, ballot_input.ballots.len())?;
    validate_disjoint_direct_ballot_randomness(
        &ballot_input
            .ballot_encryption_randomness
            .encryption_seed_hexes,
        &proof_mask_randomness.ballot_proof_randomness_hexes,
    )?;

    Ok(DirectBallotPublicPackageInput {
        public_key_material: ballot_input.public_key_material,
        public_key_material_kind: ballot_input.public_key_material_kind,
        accepted_setup_handoff_root: ballot_input.accepted_setup_handoff_root,
        ballots: ballot_input.ballots,
        ballot_encryption_randomness: ballot_input.ballot_encryption_randomness,
        proof_mask_randomness,
    })
}

fn generate_direct_ballot_public_packages_from_input(
    package_input: DirectBallotPublicPackageInput<'_>,
) -> CanonicalResult<DirectBallotPublicPackageRun> {
    let public_key = match package_input.public_key_material_kind {
        DirectBallotPublicKeyMaterialKind::AcceptedPublicKeyMaterial => {
            public_bgv_key_from_accepted_setup_public_key_material(
                package_input.public_key_material,
            )?
        }
        DirectBallotPublicKeyMaterialKind::PassiveDevelopmentSetupPackage => {
            validate_passive_setup_package_for_encrypted_evaluation(
                package_input.public_key_material,
            )?;
            public_bgv_key_from_passive_setup_package(package_input.public_key_material)?
        }
    };
    let mut encrypted_ballots = Vec::with_capacity(package_input.ballots.len());
    for ballot in package_input.ballots {
        let encrypted_ballot =
            encrypt_direct_ballot(package_input.public_key_material, &public_key, ballot)?;
        validate_direct_ballot_public_preflight(&public_key, &encrypted_ballot)?;
        encrypted_ballots.push(encrypted_ballot);
    }

    let mut proof_summaries = Vec::with_capacity(encrypted_ballots.len());
    let mut total_proving_time_milliseconds = DirectBallotTimingTotal::new();
    let mut total_verification_time_milliseconds = DirectBallotTimingTotal::new();
    for (ballot_index, encrypted_ballot) in encrypted_ballots.iter().enumerate() {
        let proof_randomness_hex = package_input
            .proof_mask_randomness
            .ballot_proof_randomness_hex(ballot_index)?;
        let proof_generation_started = DirectBallotTimingStart::now();
        let proof_generation = generate_direct_ballot_relation_proof(
            package_input.public_key_material,
            &public_key,
            encrypted_ballot,
            proof_randomness_hex,
        )?;
        let proof_transport = transport_direct_ballot_binary_proof(
            package_input.public_key_material,
            &public_key,
            encrypted_ballot,
            &proof_generation.statement_hash_hex,
            &proof_generation.proof_bytes,
            &proof_generation.proof_bytes_hash,
            direct_ballot_relation_proof_bytes_hash,
        )?;
        total_proving_time_milliseconds.add(proof_generation_started.elapsed_milliseconds());
        let proof_verification_started = DirectBallotTimingStart::now();
        let proof_verification = verify_direct_ballot_relation_proof(
            package_input.public_key_material,
            &public_key,
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

    Ok(DirectBallotPublicPackageRun {
        encrypted_ballots,
        proof_summaries,
        ballot_encryption_randomness: package_input.ballot_encryption_randomness,
        proof_mask_randomness: package_input.proof_mask_randomness,
        accepted_setup_handoff_root: package_input.accepted_setup_handoff_root,
        total_proving_time_milliseconds,
        total_verification_time_milliseconds,
    })
}

fn direct_ballot_public_package_report(
    package_run: &DirectBallotPublicPackageRun,
) -> CanonicalResult<Value> {
    let first_proof = package_run.first_proof()?;
    let total_proof_bytes = package_run.total_proof_bytes();
    let package_records = package_run
        .encrypted_ballots
        .iter()
        .zip(package_run.proof_summaries.iter())
        .enumerate()
        .map(|(ballot_index, (ballot, proof_summary))| {
            json!({
                "ballotIndex": ballot_index,
                "voterIdentity": ballot.input.voter_identity.as_str(),
                "voterRosterPosition": ballot.input.voter_roster_position,
                "actionContextHash": ballot.input.action_context_hash.as_str(),
                "encryptedBallotHash": ballot.encrypted_ballot_hash.as_str(),
                "ciphertextRoot": ballot.ciphertext_root.as_str(),
                "ciphertextCanonicalByteLength": ballot.ciphertext_canonical_byte_length,
                "statementHash": proof_summary.statement_hash_hex.as_str(),
                "proofBytesHash": proof_summary.proof_bytes_hash.as_str(),
                "proofChunkManifestRoot": proof_summary.proof_chunk_manifest_root.as_str(),
                "encryptedBallotPackageRoot": proof_summary.encrypted_ballot_package_root.as_str(),
                "proofChunkManifest": proof_summary.proof_chunk_manifest.clone(),
                "proofChunks": proof_summary.proof_chunks.clone(),
                "encryptedBallotPackage": proof_summary.encrypted_ballot_package.clone(),
                "voterSignatureSignedRoot": proof_summary.voter_signature_signed_root.clone(),
            })
        })
        .collect::<Vec<_>>();

    Ok(json!({
        "operation": DIRECT_BALLOT_PUBLIC_PACKAGE_OPERATION,
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
            "ballotCount": package_run.encrypted_ballots.len()
        },
        "encryptedBallots": {
            "encryptedBallotHashes": package_run.encrypted_ballot_hashes(),
            "ciphertextRoots": package_run.ciphertext_roots(),
            "ciphertextCanonicalByteLengths": package_run.ciphertext_byte_lengths(),
            "ballotEncryptionRandomness": package_run.ballot_encryption_randomness.report_value(),
            "result": "Direct score slots, one-hot witnesses, batch encoding, reserved zero slots, and all data-limb encryption algebra passed public-key preflight."
        },
        "encryptedBallotPackages": package_records,
        "packageCreation": {
            "setupHandoffRoot": package_run.accepted_setup_handoff_root,
            "setupBoundary": "This command requires acceptedPublicKeyMaterial plus an accepted setup handoff that binds the setup root, public-key roots, direct ballot profile hashes, and direct ballot creation policy.",
            "witnessBoundary": "This command does not accept setupPackage, setupPublicMaterial, setupPrivateWitness, top-count evaluator requests, public evaluation-key material, fixture randomness, or development randomness overrides; it creates encrypted ballot packages from accepted public-key material and fresh platform randomness only.",
            "proofBytesRetention": "Proof bytes are generated, framed as public proof chunks, chunk-hash checked, reassembled, verified, and returned as chunk records for package verification. The report still does not return witness material or randomness.",
            "signatureBoundary": "The package material is unsigned until a voter attaches an ML-DSA protocol signature envelope over voterSignatureSignedRoot. The accepted package verifier requires that envelope and an expected voter signing public-key hash.",
            "claimBoundary": "The package format, public-key relation preflight, conservative proof soundness accounting, zero-knowledge accounting, accepted verifier certificate, accepted randomness boundary, and package verification certificate are active. The package remains non-claim-bearing until mobile-compatible runtime evidence and target-decryption gates are closed."
        },
        "proofAttempt": {
            "relation": "statement-derived projected BGV data-prime encryption rows for c0=b*u+p*e0+encode(score) and c1=a*u+p*e1, with score-to-encoding carry linkage",
            "coverage": "projected BGV rows and projected no-wrap carry rows for every RNS limb component are checked by the projected response transcript; score row sums and score weighted-sum constraints are checked as exact signed integer relations against the full Fiat-Shamir challenge; the appended committed trace proof binds one-hot Booleanity, ternary randomizer support, centered-binomial error support, helper-square consistency, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score row sums, score linkage, projected BGV field rows, cross-prime no-wrap carry linkage, and packed-column shape to salted masked columns; conservative projected-BGV, committed-trace soundness, zero-knowledge budgets, the accepted verifier certificate, accepted randomness boundary, and package verification certificates are recorded",
            "proofEncoding": "internal binary feasibility encoding with appended committed trace proof",
            "sourceRingDegree": POLYNOMIAL_DEGREE,
            "rnsLimbCount": DATA_PRIMES.len(),
            "responseEncoding": "full BGV-degree signed response polynomials, direct ballot score scalars, one-hot scalars, and projected BGV no-wrap carry scalars",
            "bgvCommitmentEncoding": "statement-derived projected scalar commitments",
            "projectedBgvRelationProjectionsPerLimbComponent": DIRECT_BALLOT_PROJECTED_BGV_RELATION_PROJECTIONS_PER_LIMB_COMPONENT,
            "responsePolynomialDegree": POLYNOMIAL_DEGREE,
            "binaryRelationCommitmentBytes": first_proof.relation_commitment_bytes,
            "binarySharedResponseBytes": first_proof.response_bytes,
            "proofCount": package_run.proof_summaries.len(),
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
            "challengeSoundness": format!("single nominal {}-bit outer challenge plus independent committed-trace batching; score linkage uses exact signed integer commitments and the full challenge, projected BGV rows record a random-projection budget, committed-trace rows record a conservative soundness budget, mask/opening distributions record zero-knowledge slack, and accepted package creation refuses fixture randomness. The proof remains non-claim-bearing until mobile-compatible runtime evidence and target-decryption gates are closed", direct_ballot_relation_challenge_bits()),
            "proofAccounting": direct_ballot_relation_proof_accounting(first_proof.proof_size_bytes, total_proof_bytes)?,
            "proofTransport": {
                "encoding": "binary proof chunks",
                "status": "each generated proof is framed into fixed-size binary chunks, chunk-hash checked, root-checked, reassembled, and verified from the transported bytes",
                "retention": "proof chunks are returned in encryptedBallotPackages[].proofChunks for package verification; reassembled proof bytes are verified internally and not returned as one monolithic field",
                "chunkSizeBytes": DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
                "chunksPerProof": first_proof.proof_chunk_count,
                "chunksForBatch": chunk_count_for_bytes(total_proof_bytes, DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES)?,
                "transportedProofSizeBytes": first_proof.transported_proof_size_bytes,
                "transportedProofBytesHash": first_proof.transported_proof_bytes_hash,
                "firstProofChunkMerkleRoot": first_proof.proof_chunk_merkle_root,
                "firstProofChunkHashes": first_proof.proof_chunk_hashes,
                "firstProofChunkManifestRoot": first_proof.proof_chunk_manifest_root,
                "firstProofChunkManifest": first_proof.proof_chunk_manifest,
                "firstEncryptedBallotPackageRoot": first_proof.encrypted_ballot_package_root,
                "firstEncryptedBallotPackage": first_proof.encrypted_ballot_package,
                "firstVoterSignatureSignedRoot": first_proof.voter_signature_signed_root,
                "firstProofStatementHash": first_proof.statement_hash_hex,
                "proofProfileHash": direct_ballot_relation_proof_profile_hash()?,
                "arithmeticCertificateHash": direct_ballot_arithmetic_certificate_hash()?,
                "soundnessCertificateHash": direct_ballot_soundness_certificate_hash()?,
                "zeroKnowledgeCertificateHash": direct_ballot_zero_knowledge_certificate_hash()?,
                "verifierCertificateHash": direct_ballot_verifier_certificate_hash()?
            },
            "proofCostEvidence": {
                "evidencePath": "accepted public encrypted ballot package creation",
                "proofSizeBytes": first_proof.proof_size_bytes,
                "proofChunkSizeBytes": DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
                "proofChunkCount": first_proof.proof_chunk_count,
                "totalProofBytes": total_proof_bytes,
                "kernelTimingStatus": direct_ballot_timing_status(),
                "kernelProvingTimeMilliseconds": package_run.total_proving_time_milliseconds.report_value(),
                "kernelVerificationTimeMilliseconds": package_run.total_verification_time_milliseconds.report_value(),
                "wasmRuntimeEvidence": "When invoked through the WASM bridge, the top-level wasmRuntimeEvidence field records command wall time, request and response byte lengths, JS/WASM copy count, largest copied buffer, and linear-memory peak for the command. The wasm32-unknown-unknown kernel does not expose separate internal prove and verify phase timers."
            },
            "proofMaskRandomness": package_run.proof_mask_randomness.report_value(),
            "relationCommitmentScalarCount": first_proof.relation_commitment_scalar_count,
            "sharedResponsePolynomialCount": first_proof.shared_response_polynomial_count,
            "sharedResponseScalarCount": first_proof.shared_response_scalar_count,
            "responseSharing": "one binary response vector is checked against statement-derived projected BGV rows, projected no-wrap carry rows, and score-linear constraints; support rows are checked by the appended committed trace proof; response bytes are not duplicated per limb",
            "timingStatus": direct_ballot_timing_status(),
            "provingTimeMilliseconds": package_run.total_proving_time_milliseconds.report_value(),
            "verificationTimeMilliseconds": package_run.total_verification_time_milliseconds.report_value(),
            "proofGate": first_proof.proof_gate,
            "generation": "Generated and verified one binary proof with projected all-limb BGV encryption rows, exact integer score-linear constraints, and an appended committed trace proof for support, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score, projected BGV field, and cross-prime no-wrap carry rows. Conservative soundness, zero-knowledge accounting, the accepted verifier certificate, and the accepted randomness boundary are recorded for this proof profile; the proof model is not claim-bearing until mobile-compatible runtime evidence and target-decryption gates are closed.",
            "projectedRnsCoverage": "The proof derives projected rows for all 17 BGV RNS limbs with one shared randomizer, error, encoding-carry, score, and one-hot response vector, while score linkage uses exact integer commitments outside the plaintext modulus.",
            "blocker": "Next missing pieces are mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, target share proof certification, smudging/noise C1-C4 closure, and public target-decryption integration. The development command may still use development-deterministic-fixture proof masks or ballot-encryption randomness, and those runs remain fixture evidence only."
        },
        "decision": "Direct BGV ballot encryption, all-limb public-key preflight, one widened shared-response proof with exact integer score linkage, recorded projected-BGV soundness, committed-trace soundness, zero-knowledge budgets, accepted verifier certification, accepted randomness boundaries, package-level binary proof chunk manifests, and internal public-artifact package verification are the public package creation path. They are not claim-bearing because mobile evidence, target share proof/C1-C4, and public target-decryption gates are not closed."
    }))
}

fn validate_accepted_direct_ballot_package_randomness(
    package_input: &DirectBallotPublicPackageInput<'_>,
) -> CanonicalResult<()> {
    if package_input.ballot_encryption_randomness.source
        != DirectBallotEncryptionRandomnessSource::FreshCsprng
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "createDirectEncryptedBallotPackages requires ballotEncryptionRandomness.source to be fresh-csprng; development-deterministic-fixture is accepted only by runDirectEncryptedBallot",
        ));
    }
    if package_input.proof_mask_randomness.source
        != DirectBallotProofMaskRandomnessSource::FreshCsprng
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "createDirectEncryptedBallotPackages requires proofMaskRandomness.source to be fresh-csprng; development-deterministic-fixture is accepted only by runDirectEncryptedBallot",
        ));
    }

    Ok(())
}

fn reject_public_package_private_fields(request: &Value) -> CanonicalResult<()> {
    if request.get("setupPackage").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "createDirectEncryptedBallotPackages uses acceptedPublicKeyMaterial and acceptedSetupHandoff; setupPackage is only accepted by the development command",
        ));
    }
    if request.get("setupPublicMaterial").is_some() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "createDirectEncryptedBallotPackages uses acceptedPublicKeyMaterial; setupPublicMaterial is passive setup material and is not accepted here",
        ));
    }
    for field_name in [
        "setupPrivateWitness",
        "topCount",
        "topCounts",
        "publicEvaluationKeyMaterial",
        "targetFinalityPolicyHash",
    ] {
        if request.get(field_name).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("createDirectEncryptedBallotPackages does not accept {field_name}"),
            ));
        }
    }

    Ok(())
}
