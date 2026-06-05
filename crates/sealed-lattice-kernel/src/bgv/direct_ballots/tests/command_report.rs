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
                "actionContextHash": derive_protocol_hash(
                    "ActionContextHash",
                    &json!({ "action": "direct encrypted ballot test" }),
                ).expect("action hash"),
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
            "all RNS limb encryption equations, score-to-encoding linkage, exactly-one bucket sums, score weighted-sum constraints, one-hot Booleanity, randomizer support, and error support are checked by one internal binary transcript; claim soundness and zero-knowledge are not accepted for the current proof model"
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
        Some(18_626_400)
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
        Some(47)
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
        Some(18_626_400 * 8)
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
        Some(18)
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
        18
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["firstProofPublicTransportHash"]
            .as_str()
            .expect("first proof public transport hash")
            .len(),
        128
    );
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
            "Next missing pieces are accepted weakest-relation soundness accounting, replacement or formal redesign of witness-dependent support commitments, Fiat-Shamir/QROM review, mobile runtime evidence, browser/mobile proof-copy measurement, mobile memory evidence, public package proof transport for an accepted proof profile, public accepted randomness API boundaries, target share proof certification, smudging/noise C1-C4 closure, and public target-decryption integration. Runs using development-deterministic-fixture proof masks or ballot-encryption randomness remain fixture evidence only."
        )
    );
    assert_eq!(
        result["proofAttempt"]["responseSharing"].as_str(),
        Some(
            "one binary response vector is checked against all 17 RNS limb equations, score-linear constraints, and support constraints; response bytes are not duplicated per limb"
        )
    );
    assert_eq!(
        result["proofAttempt"]["sharedScoreResponseScalarCount"].as_u64(),
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
        Some("full BGV-degree signed response polynomials plus direct ballot score scalars")
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
