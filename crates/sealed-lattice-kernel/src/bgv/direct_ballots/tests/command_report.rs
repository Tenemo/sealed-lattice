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
                "actionContextHash": derive_canonical_object_hash(
                    &json!({ "objectType": "ActionContextHash", "action": "direct encrypted ballot test" }),
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
    assert!(
        result["proofAttempt"]["proofAccounting"]
            ["zeroKnowledgeShiftSlackBitsAfterResponseUnionBound"]
            .as_u64()
            .expect("zero-knowledge shift slack bits")
            >= 128
    );
    assert_eq!(
        result["proofAttempt"]["proofTransport"]["encoding"].as_str(),
        Some("binary proof chunks")
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
        result["proofAttempt"]["proofTransport"]["proofParametersHash"]
            .as_str()
            .expect("proof parameters hash")
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
        result["evaluatorReplay"].as_str(),
        Some(
            "Not run in this command. Supply topCount to attempt the packed batched-pair evaluator route over the direct aggregate."
        )
    );
}
