use super::*;

#[test]
fn direct_encrypted_ballot_command_reports_current_proof_status() {
    let setup_package = setup_package();
    let result = run_direct_encrypted_ballot(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": DIRECT_BALLOT_TEST_SETUP_SEED
        },
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            {
                "voterIdentity": "voter-1",
                "voterRosterPosition": 0,
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot test" }),
                ).expect("action hash"),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "scores": [
                    10, 9, 8, 7, 6,
                    5, 4, 3, 2, 1,
                    1, 2, 3, 4, 5,
                    6, 7, 8, 9, 10
                ]
            }
        ]
    }))
    .expect("direct encrypted ballot command succeeds");

    assert_eq!(
        result["proofAttempt"]["coverage"].as_str(),
        Some(
            "projected BGV rows and projected no-wrap carry rows for every RNS limb component, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, and statement-derived random-projected support are checked by the projected response transcript; an appended committed trace proof also binds one-hot Booleanity, ternary randomizer support, centered-binomial error support, helper-square consistency, encoder carry bit/slack range, projected no-wrap carry ternary-digit range, score row sums, score linkage, projected BGV field rows, cross-prime no-wrap carry linkage, and packed-column shape to salted masked columns; claim soundness, Fiat-Shamir/QROM accounting, and zero-knowledge are not accepted"
        )
    );
    assert!(
        result["proofAttempt"]["generation"]
            .as_str()
            .expect("proof generation assessment")
            .starts_with("Generated and verified one internal binary proof")
    );
    assert_eq!(
        result["proofAttempt"]["proofSizeBytes"],
        result["proofAttempt"]["verifiedProofSizeBytes"]
    );
    assert_eq!(
        result["proofAttempt"]["proofSizeBytes"].as_u64(),
        Some(31_570_776)
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]["challengeBits"].as_u64(),
        Some(192)
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]["proofModelAccepted"].as_bool(),
        Some(false)
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]["weakestRelationEffectiveBitsPerCheck"].as_u64(),
        Some(16)
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]["supportRelationModulusBits"].as_u64(),
        Some(141)
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]["targetClassicalSoundnessBits"].as_u64(),
        Some(128)
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]["minimumIndependentRepetitionsForTarget"],
        Value::Null
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]
            ["estimatedIndependentRepetitionsFromWeakestRelationBeforeUnionLosses"]
            .as_u64(),
        Some(8)
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]["estimatedRepeatedProofSizeBytes"].as_u64(),
        Some(31_570_776 * 8)
    );
    assert_eq!(
        result["proofAttempt"]["proofAccounting"]["classicalSoundnessBitsAfterSupportUnionBound"],
        Value::Null
    );
    assert!(
        result["proofAttempt"]["proofAccounting"]
            ["zeroKnowledgeShiftSlackBitsAfterResponseUnionBound"]
            .as_u64()
            .expect("zero-knowledge shift slack bits")
            >= 128
    );
    assert!(
        result["proofAttempt"]["proofAccounting"]["decision"]
            .as_str()
            .expect("proof accounting decision")
            .contains("claim soundness is not accepted")
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["encoding"].as_str(),
        Some("binary proof chunks")
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["status"].as_str(),
        Some(
            "each generated proof is framed into fixed-size binary chunks, chunk-hash checked, root-checked, reassembled, and verified from the transported bytes"
        )
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["chunkSizeBytes"].as_u64(),
        Some(
            u64::try_from(DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES).expect("chunk size fits u64")
        )
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["chunksPerProof"].as_u64(),
        Some(31)
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["transportedProofSizeBytes"],
        result["proofAttempt"]["proofSizeBytes"]
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["transportedProofBytesHash"],
        result["proofAttempt"]["proofBytesHash"]
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstProofChunkMerkleRoot"]
            .as_str()
            .expect("first proof chunk Merkle root")
            .len(),
        128
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstProofChunkHashes"]
            .as_array()
            .expect("first proof chunk hashes")
            .len(),
        31
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstProofChunkManifestRoot"]
            .as_str()
            .expect("first proof chunk manifest root")
            .len(),
        128
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstProofChunkManifest"]["objectType"].as_str(),
        Some("BallotProofChunkManifest")
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstProofChunkManifest"]["statementHash"],
        result["proofAttempt"]["proofTransport"]["firstProofStatementHash"]
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstEncryptedBallotPackageRoot"]
            .as_str()
            .expect("first encrypted ballot package root")
            .len(),
        128
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstEncryptedBallotPackage"]["objectType"]
            .as_str(),
        Some("EncryptedBallotPackage")
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstEncryptedBallotPackage"]["proofChunkRoot"],
        result["proofAttempt"]["proofTransport"]["firstProofChunkManifestRoot"]
    );
    let package_json =
        canonical_json(&result["proofAttempt"]["proofTransport"]["firstEncryptedBallotPackage"])
            .expect("package should serialize canonically");
    for forbidden_field in [
        "scoreHash",
        "plaintextScores",
        "scoreCommitment",
        "encryptionRandomness",
        "proofWitness",
        "proofRandomnessSeed",
        "fixtureSeed",
        "oracleResult",
        "developmentPlaintext",
    ] {
        assert!(
            !package_json.contains(forbidden_field),
            "{forbidden_field} must not appear in package"
        );
    }
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["proofProfileHash"]
            .as_str()
            .expect("proof profile hash")
            .len(),
        128
    );
    assert_eq!(
        result["proofAttempt"]["proofMaskRandomness"]["source"].as_str(),
        Some(DIRECT_BALLOT_PROOF_MASK_RANDOMNESS_DEVELOPMENT_FIXTURE)
    );
    assert_eq!(
        result["proofAttempt"]["proofMaskRandomness"]["ballotProofRandomnessCount"].as_u64(),
        Some(1)
    );
    assert_eq!(
        result["proofAttempt"]["blocker"].as_str(),
        Some(
            "Next missing pieces are accepted weakest-relation soundness accounting, committed-trace zero-knowledge accounting, Fiat-Shamir/QROM accounting, mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, accepted package verifier closure for the proof profile, public accepted randomness API boundaries, target share proof certification, smudging/noise C1-C4 closure, and public target-decryption integration. Runs using development-deterministic-fixture proof masks or ballot-encryption randomness remain fixture evidence only."
        )
    );
    assert_eq!(
        result["proofAttempt"]["responseSharing"].as_str(),
        Some(
            "one binary response vector is checked against statement-derived projected BGV rows, projected no-wrap carry rows, score-linear constraints, and support constraints; response bytes are not duplicated per limb"
        )
    );
    assert_eq!(
        result["proofAttempt"]["sharedResponseScalarCount"].as_u64(),
        Some(
            u64::try_from(super::relation_proof::direct_ballot_relation_response_scalar_count())
                .expect("response scalar count fits u64")
        )
    );
    assert_eq!(
        result["proofAttempt"]["rnsLimbCount"].as_u64(),
        Some(u64::try_from(DATA_PRIMES.len()).expect("limb count fits u64"))
    );
    assert_eq!(
        result["proofAttempt"]["responseEncoding"].as_str(),
        Some(
            "full BGV-degree signed response polynomials, direct ballot score scalars, one-hot scalars, and projected BGV no-wrap carry scalars"
        )
    );
    assert_eq!(
        result["proofAttempt"]["bgvCommitmentEncoding"].as_str(),
        Some("statement-derived projected scalar commitments")
    );
    assert_eq!(
        result["proofAttempt"]["projectedBgvRelationProjectionsPerLimbComponent"].as_u64(),
        Some(3)
    );
    assert_eq!(
        result["proofAttempt"]["responsePolynomialDegree"].as_u64(),
        Some(u64::try_from(POLYNOMIAL_DEGREE).expect("polynomial degree fits u64"))
    );
    let proof_attempt = result["proofAttempt"]
        .as_object()
        .expect("proof attempt is an object");
    assert!(proof_attempt.get("proofRingDegree").is_none());
    assert!(proof_attempt.get("statementRowsPerLimb").is_none());
    assert!(proof_attempt.get("statementColumnsPerLimb").is_none());
    assert!(proof_attempt.get("totalRnsEquationRows").is_none());
    assert_eq!(proof_attempt.get("sharedShortResponseVectorLength"), None);
    assert_eq!(
        proof_attempt.get("duplicatedShortResponseVectorLength"),
        None
    );
    assert_eq!(
        result["encryptedBallots"]["ciphertextRoots"]
            .as_array()
            .expect("ciphertext roots")
            .len(),
        1
    );
    assert_eq!(
        result["encryptedBallots"]["ballotEncryptionRandomness"]["source"].as_str(),
        Some(DIRECT_BALLOT_ENCRYPTION_RANDOMNESS_DEVELOPMENT_FIXTURE)
    );
    assert_eq!(
        result["encryptedBallots"]["ballotEncryptionRandomness"]["ballotEncryptionRandomnessCount"]
            .as_u64(),
        Some(1)
    );
    assert_eq!(
        result["encryptedBallots"]["ballotEncryptionRandomness"]["randomnessBytesPerBallot"]
            .as_u64(),
        Some(32)
    );
    assert!(
        result["encryptedBallots"]["ballotEncryptionRandomness"]["retention"]
            .as_str()
            .expect("encryption randomness retention")
            .contains("not returned")
    );
    assert_eq!(result["aggregation"]["ballotCount"].as_u64(), Some(1));
    assert_eq!(
        result["aggregation"]["result"].as_str(),
        Some(
            "Verified the supplied direct ballot proofs, aggregated their ciphertexts, and privately checked the aggregate against the plaintext oracle without publishing aggregate scores."
        )
    );
    assert!(result["aggregation"].get("aggregateScores").is_none());
    assert!(result["aggregation"].get("plaintextOracleScores").is_none());
    assert_eq!(
        result["aggregation"]["privateCorrectnessCheck"].as_str(),
        Some("aggregate score slots matched the plaintext oracle")
    );
    assert_eq!(
        result["evaluatorReplay"].as_str(),
        Some(
            "Not run in this command. Supply topCount to attempt the packed batched-pair evaluator route over the direct aggregate."
        )
    );
}

#[test]
fn direct_encrypted_ballot_public_package_command_reports_package_artifacts() {
    let setup_package = setup_package();
    let public_material_fixture = accepted_direct_ballot_public_material_fixture(&setup_package);
    let result = create_direct_encrypted_ballot_packages(&json!({
        "acceptedPublicKeyMaterial": public_material_fixture.accepted_public_key_material,
        "acceptedSetupHandoff": public_material_fixture.accepted_setup_handoff.clone(),
        "ballotEncryptionRandomness": direct_ballot_test_ballot_encryption_randomness(1),
        "proofMaskRandomness": direct_ballot_test_proof_mask_randomness(1),
        "ballots": [
            direct_ballot_test_ballot_json("voter-public-package", 0)
        ]
    }))
    .expect("direct encrypted ballot public package command succeeds");

    assert_eq!(
        result["operation"].as_str(),
        Some(DIRECT_BALLOT_PUBLIC_PACKAGE_OPERATION)
    );
    assert_eq!(result["input"]["ballotCount"].as_u64(), Some(1));
    assert!(result.get("aggregation").is_none());
    assert!(result.get("evaluatorReplay").is_none());
    assert!(
        result["packageCreation"]["witnessBoundary"]
            .as_str()
            .expect("witness boundary")
            .contains("does not accept setupPackage")
    );
    assert_eq!(
        result["packageCreation"]["setupHandoffRoot"],
        public_material_fixture.accepted_setup_handoff["acceptedSetupHandoffRoot"]
    );
    assert!(
        result["packageCreation"]["proofBytesRetention"]
            .as_str()
            .expect("proof byte retention")
            .contains("returned as chunk records")
    );
    assert_eq!(
        result["encryptedBallots"]["result"].as_str(),
        Some(
            "Direct score slots, one-hot witnesses, batch encoding, reserved zero slots, and all data-limb encryption algebra passed public-key preflight."
        )
    );

    let package_records = result["encryptedBallotPackages"]
        .as_array()
        .expect("package records");
    assert_eq!(package_records.len(), 1);
    let package_record = &package_records[0];
    let proof_transport = &result["proofAttempt"]["proofTransport"];

    assert_eq!(
        package_record["statementHash"],
        proof_transport["firstProofStatementHash"]
    );
    assert_eq!(
        package_record["proofBytesHash"],
        result["proofAttempt"]["proofBytesHash"]
    );
    assert_eq!(
        package_record["proofChunkManifestRoot"],
        proof_transport["firstProofChunkManifestRoot"]
    );
    assert_eq!(
        package_record["encryptedBallotPackageRoot"],
        proof_transport["firstEncryptedBallotPackageRoot"]
    );
    assert_eq!(
        package_record["proofChunkManifest"]["objectType"].as_str(),
        Some("BallotProofChunkManifest")
    );
    assert_eq!(
        package_record["proofChunkManifest"]["chunkCount"],
        proof_transport["chunksPerProof"]
    );
    assert_eq!(
        package_record["proofChunks"]
            .as_array()
            .expect("public proof chunks")
            .len(),
        proof_transport["chunksPerProof"]
            .as_u64()
            .expect("chunks per proof") as usize
    );
    assert_eq!(
        package_record["proofChunks"][0]["chunkHash"],
        package_record["proofChunkManifest"]["chunkHashList"][0]
    );
    assert!(
        package_record["proofChunks"][0]["bytesHex"]
            .as_str()
            .expect("chunk bytes")
            .len()
            > DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES
    );
    assert_eq!(
        package_record["encryptedBallotPackage"]["objectType"].as_str(),
        Some("EncryptedBallotPackage")
    );
    assert_eq!(
        package_record["encryptedBallotPackage"]["ciphertextTransport"]["canonicalByteLength"],
        package_record["ciphertextCanonicalByteLength"]
    );
    assert!(
        package_record["encryptedBallotPackage"]["ciphertextTransport"]["canonicalBytesHex"]
            .as_str()
            .expect("ciphertext canonical bytes")
            .len()
            == package_record["ciphertextCanonicalByteLength"]
                .as_u64()
                .expect("ciphertext byte length") as usize
                * 2
    );
    assert_eq!(
        package_record["encryptedBallotPackage"]["proofChunkRoot"],
        package_record["proofChunkManifestRoot"]
    );
    assert_eq!(
        package_record["encryptedBallotPackage"]["proofStatementHash"],
        package_record["statementHash"]
    );

    let package_json = canonical_json(&package_record["encryptedBallotPackage"])
        .expect("package should serialize canonically");
    for forbidden_field in [
        "scoreHash",
        "plaintextScores",
        "scoreCommitment",
        "encryptionRandomness",
        "proofWitness",
        "proofRandomnessSeed",
        "fixtureSeed",
        "oracleResult",
        "developmentPlaintext",
        "setupPrivateWitness",
    ] {
        assert!(
            !package_json.contains(forbidden_field),
            "{forbidden_field} must not appear in package"
        );
    }
}
