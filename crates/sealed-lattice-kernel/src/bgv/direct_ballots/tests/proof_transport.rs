use super::*;

#[test]
fn direct_ballot_public_proof_transport_rejects_wrong_chunk_hash() {
    let fixture = direct_ballot_relation_proof_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.setup_package,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut chunk_hashes = transport.chunk_hashes.clone();
    chunk_hashes[0] = "0".repeat(128);

    let error = verify_direct_ballot_public_proof_transport(
        &transport.proof_bytes,
        &transport.proof_bytes_hash,
        &chunk_hashes,
        DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
        &transport.chunk_merkle_root,
    )
    .expect_err("wrong chunk hash must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("chunk 0 hash does not match"));
}

#[test]
fn direct_ballot_public_proof_transport_rejects_duplicate_chunk_hash() {
    let fixture = direct_ballot_relation_proof_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.setup_package,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut chunk_hashes = transport.chunk_hashes.clone();
    chunk_hashes[1] = chunk_hashes[0].clone();

    let error = verify_direct_ballot_public_proof_transport(
        &transport.proof_bytes,
        &transport.proof_bytes_hash,
        &chunk_hashes,
        DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
        &transport.chunk_merkle_root,
    )
    .expect_err("duplicate chunk hash must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("contains a duplicate chunk hash"));
}

#[test]
fn direct_ballot_public_proof_transport_rejects_truncated_proof_bytes() {
    let fixture = direct_ballot_relation_proof_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.setup_package,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let truncated_len = transport
        .proof_bytes
        .len()
        .checked_sub(1)
        .expect("proof has bytes");

    let error = verify_direct_ballot_public_proof_transport(
        &transport.proof_bytes[..truncated_len],
        &transport.proof_bytes_hash,
        &transport.chunk_hashes,
        DIRECT_BALLOT_PROTOTYPE_PROOF_CHUNK_BYTES,
        &transport.chunk_merkle_root,
    )
    .expect_err("truncated proof bytes must reject");

    assert!(
        error
            .message
            .contains("chunk hash count does not match proof length")
            || error.message.contains("hash does not match")
            || error.message.contains("full proof hash does not match")
            || error.message.contains("chunk Merkle root does not match")
    );
}

#[test]
fn direct_ballot_proof_chunk_manifest_binds_statement_and_package_roots() {
    let fixture = direct_ballot_relation_proof_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.setup_package,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");

    assert_eq!(
        transport.proof_chunk_manifest["objectType"].as_str(),
        Some("BallotProofChunkManifest")
    );
    assert_eq!(
        transport.proof_chunk_manifest["statementHash"].as_str(),
        Some(fixture.proof_generation.statement_hash_hex.as_str())
    );
    assert_eq!(
        transport.encrypted_ballot_package["objectType"].as_str(),
        Some("EncryptedBallotPackage")
    );
    assert!(
        transport.encrypted_ballot_package["proofStatement"].is_null(),
        "the public package carries only the statement hash, not statement JSON"
    );
    assert_eq!(
        transport.encrypted_ballot_package["proofChunkRoot"].as_str(),
        Some(transport.proof_chunk_manifest_root.as_str())
    );
    assert_eq!(
        transport.encrypted_ballot_package["signature"]["objectType"].as_str(),
        Some("DevelopmentEncryptedBallotPackageSignaturePlaceholder")
    );
    assert_eq!(
        transport.encrypted_ballot_package["signature"]["proofStatementHash"].as_str(),
        Some(fixture.proof_generation.statement_hash_hex.as_str())
    );
}

#[test]
fn direct_ballot_package_schema_roots_match_stable_fixture_vectors() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");

    assert_eq!(
        fixture.proof_generation.statement_hash_hex,
        "44ff914c86e91b5496382adde44c62671678e1b7a002cadb44fb25ed57d992ed930fec58a93c66eaa68f63d9202289fadd9a04dd14fb5cd06333b69c958d9b9c"
    );
    assert_eq!(
        fixture.proof_generation.proof_bytes_hash,
        "258ffe33b6d62ffd6a460edf3ca4ed8fc9cb63c2fa9bf0fe58066d0c7c4024c696ea198739220fc21162b7d5682cfe3ad80f7629c4eeab452082963917fada90"
    );
    assert_eq!(
        transport.proof_chunk_manifest_root,
        "3778c7bbab9f94fc711eba9bdb91646d57671ee95891c272c42ba3a81d2e35256fe3c0706276c510c1291d571033bf19101a3f61a88785239b883e19a3f009fc"
    );
    assert_eq!(
        transport.encrypted_ballot_package_root,
        "dd061170efba8981c1e1eddc0abdf075bc705fb8063cb90996ed35b0928649122b58478c2123a4cb3e2213cd4c9ec8feaad9918e05672a8e3d01d905704689a6"
    );
}

#[test]
fn direct_ballot_package_verifier_accepts_public_package_and_chunks() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");

    let result = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "encryptedBallotPackage": transport.encrypted_ballot_package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect("package verifier accepts public artifacts");

    assert_eq!(
        result["operation"].as_str(),
        Some(VERIFY_DIRECT_BALLOT_PACKAGE_OPERATION)
    );
    assert_eq!(
        result["verificationStatus"].as_str(),
        Some(
            "setup handoff, public package artifacts, and internal direct ballot relation proof verified"
        )
    );
    assert_eq!(
        result["acceptedSetupHandoffRoot"],
        fixture.accepted_setup_handoff["acceptedSetupHandoffRoot"]
    );
    assert_eq!(
        result["packageRoot"].as_str(),
        Some(transport.encrypted_ballot_package_root.as_str())
    );
    assert_eq!(
        result["proofStatementHash"].as_str(),
        Some(fixture.proof_generation.statement_hash_hex.as_str())
    );
    assert_eq!(
        result["verifiedStatementHash"].as_str(),
        Some(fixture.proof_generation.statement_hash_hex.as_str())
    );
    assert_eq!(
        result["proofBytesHash"].as_str(),
        Some(fixture.proof_generation.proof_bytes_hash.as_str())
    );
    assert_eq!(
        result["proofChunkRoot"].as_str(),
        Some(transport.proof_chunk_manifest_root.as_str())
    );
    assert_eq!(
        result["proofChunkCount"].as_u64(),
        Some(u64::try_from(transport.chunk_count).expect("chunk count fits u64"))
    );
    assert!(
        result["claimBoundary"]
            .as_str()
            .expect("claim boundary")
            .contains("development evidence")
    );
}

#[test]
fn direct_ballot_package_verifier_rejects_tampered_public_chunk_bytes() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut proof_chunks = transport.proof_chunks.clone();
    let chunk_bytes_hex = proof_chunks[0]["bytesHex"]
        .as_str()
        .expect("chunk bytes hex");
    let replacement_prefix = if chunk_bytes_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    let tampered_chunk_bytes_hex = format!("{replacement_prefix}{}", &chunk_bytes_hex[1..]);
    proof_chunks[0]["bytesHex"] = json!(tampered_chunk_bytes_hex);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "encryptedBallotPackage": transport.encrypted_ballot_package,
        "proofChunks": proof_chunks,
    }))
    .expect_err("tampered chunk bytes must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("bytes do not match chunkHash"));
}

#[test]
fn direct_ballot_package_verifier_rejects_forbidden_package_fields() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut package = transport.encrypted_ballot_package.clone();
    package["plaintextScores"] = json!([1, 2, 3]);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "encryptedBallotPackage": package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("forbidden plaintext field must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("plaintextScores"));
}

#[test]
fn direct_ballot_package_verifier_rejects_unexpected_package_fields_after_root_rebinding() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut package = transport.encrypted_ballot_package.clone();
    package["proofStatement"] = json!({
        "statementId": "BallotValidityStatement-v1",
        "statementHash": fixture.proof_generation.statement_hash_hex,
    });
    rebind_encrypted_ballot_package_root(&mut package);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "encryptedBallotPackage": package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("package with an embedded statement object must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("unexpected field proofStatement"));
}

#[test]
fn direct_ballot_package_verifier_rejects_package_context_drift_after_root_rebinding() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut package = transport.encrypted_ballot_package.clone();
    package["manifestHash"] = json!("0".repeat(128));
    rebind_encrypted_ballot_package_root(&mut package);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "encryptedBallotPackage": package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("package context drift must reject even after root rebinding");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("manifestHash"));
    assert!(error.message.contains("rebuilt statement"));
}

#[test]
fn direct_ballot_package_verifier_rejects_layout_and_encoder_drift_after_root_rebinding() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");

    for field_name in [
        "batchLayoutBindingHash",
        "ballotScoreEncodingProfileHash",
        "encryptedBallotLayoutHash",
        "directBallotReservedSlotRuleHash",
        "directBallotEncoderMatrixRoot",
        "witnessPartitionProfileHash",
        "arithmeticCertificateHash",
    ] {
        let mut package = transport.encrypted_ballot_package.clone();
        package[field_name] = json!("0".repeat(128));
        rebind_encrypted_ballot_package_root(&mut package);

        let error = verify_direct_encrypted_ballot_package(&json!({
            "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
            "acceptedSetupHandoff": fixture.accepted_setup_handoff,
            "encryptedBallotPackage": package,
            "proofChunks": transport.proof_chunks,
        }))
        .expect_err("layout and encoder drift must reject after root rebinding");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(error.message.contains(field_name));
        assert!(error.message.contains("rebuilt statement"));
    }
}

#[test]
fn direct_ballot_package_verifier_rejects_unexpected_chunk_manifest_fields() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut package = transport.encrypted_ballot_package.clone();
    package["proofChunkManifest"]["legacyStatementObject"] = json!({});
    let proof_chunk_root = derive_protocol_hash(
        "BallotProofChunkManifestRoot",
        &package["proofChunkManifest"],
    )
    .expect("manifest root");
    package["proofChunkRoot"] = json!(proof_chunk_root);
    rebind_encrypted_ballot_package_root(&mut package);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "encryptedBallotPackage": package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("manifest with an unexpected field must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("proofChunkManifest"));
    assert!(
        error
            .message
            .contains("unexpected field legacyStatementObject")
    );
}

#[test]
fn direct_ballot_package_verifier_rejects_unexpected_public_chunk_fields() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut proof_chunks = transport.proof_chunks.clone();
    proof_chunks[0]["legacyBytes"] = json!("00");

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "encryptedBallotPackage": transport.encrypted_ballot_package,
        "proofChunks": proof_chunks,
    }))
    .expect_err("proof chunk with an unexpected field must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("proofChunks[0]"));
    assert!(error.message.contains("unexpected field legacyBytes"));
}

#[test]
fn direct_ballot_package_verifier_rejects_under_bound_signature_placeholder() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut package = transport.encrypted_ballot_package.clone();
    package["signature"]["proofChunkRoot"] = json!("0".repeat(128));

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "encryptedBallotPackage": package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("signature placeholder with a wrong proof chunk root must reject");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(error.message.contains("proofChunkRoot"));
}

#[test]
fn direct_ballot_package_verifier_rejects_rebound_handoff_for_wrong_setup_root() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut accepted_setup_handoff = fixture.accepted_setup_handoff.clone();
    accepted_setup_handoff["setupPackageHash"] = json!("0".repeat(128));
    rebind_accepted_setup_handoff_root(&mut accepted_setup_handoff);
    let mut accepted_public_key_material = fixture.accepted_public_key_material.clone();
    accepted_public_key_material["acceptedSetupHandoffRoot"] =
        accepted_setup_handoff["acceptedSetupHandoffRoot"].clone();

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material,
        "acceptedSetupHandoff": accepted_setup_handoff,
        "encryptedBallotPackage": transport.encrypted_ballot_package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("setup root mismatch must reject");

    assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
    assert!(
        error
            .message
            .contains("acceptedPublicKeyMaterial.setupPackageHash")
    );
}

#[test]
fn direct_ballot_package_verifier_rejects_rebound_handoff_layout_and_encoder_drift() {
    let fixture = direct_ballot_accepted_package_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.accepted_public_key_material,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");

    for field_name in [
        "batchLayoutBindingHash",
        "ballotScoreEncodingProfileHash",
        "encryptedBallotLayoutHash",
        "directBallotReservedSlotRuleHash",
        "directBallotEncoderMatrixRoot",
        "witnessPartitionProfileHash",
        "arithmeticCertificateHash",
    ] {
        let mut accepted_setup_handoff = fixture.accepted_setup_handoff.clone();
        accepted_setup_handoff["directBallotEncryptionHandoff"][field_name] =
            json!("0".repeat(128));
        rebind_accepted_setup_handoff_root(&mut accepted_setup_handoff);
        let mut accepted_public_key_material = fixture.accepted_public_key_material.clone();
        accepted_public_key_material["acceptedSetupHandoffRoot"] =
            accepted_setup_handoff["acceptedSetupHandoffRoot"].clone();

        let error = verify_direct_encrypted_ballot_package(&json!({
            "acceptedPublicKeyMaterial": accepted_public_key_material,
            "acceptedSetupHandoff": accepted_setup_handoff,
            "encryptedBallotPackage": transport.encrypted_ballot_package,
            "proofChunks": transport.proof_chunks,
        }))
        .expect_err("rebound handoff layout and encoder drift must reject");

        assert_eq!(error.code, CanonicalErrorCode::ProfileComponentMismatch);
        assert!(error.message.contains(field_name));
    }
}

#[test]
fn direct_ballot_proof_chunk_manifest_rejects_statement_tampering() {
    let fixture = direct_ballot_relation_proof_fixture();
    let transport = transport_direct_ballot_binary_proof(
        &fixture.setup_package,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.statement_hash_hex,
        &fixture.proof_generation.proof_bytes,
        &fixture.proof_generation.proof_bytes_hash,
        direct_ballot_relation_proof_bytes_hash,
    )
    .expect("proof transport");
    let mut tampered_manifest = transport.proof_chunk_manifest.clone();
    tampered_manifest["statementHash"] = json!("0".repeat(128));

    let error =
        verify_direct_ballot_proof_chunk_manifest(&tampered_manifest, &transport.proof_bytes)
            .expect_err("tampered statement hash must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("statementHash"));
}

fn rebind_encrypted_ballot_package_root(package: &mut Value) {
    let package_object = package
        .as_object()
        .expect("encrypted ballot package object")
        .clone();
    let signature = package_object
        .get("signature")
        .expect("signature placeholder")
        .clone();
    let mut unsigned_package = package_object;
    unsigned_package.remove("packageRoot");
    unsigned_package.remove("signature");
    let package_root = derive_protocol_hash(
        "EncryptedBallotPackageRoot",
        &Value::Object(unsigned_package),
    )
    .expect("package root");
    package["packageRoot"] = json!(package_root.clone());
    package["signature"] = signature;
    package["signature"]["signedObjectRoot"] = json!(package_root);
    if let Some(proof_chunk_root) = package["proofChunkRoot"].as_str().map(ToString::to_string) {
        package["signature"]["proofChunkRoot"] = json!(proof_chunk_root);
    }
    if let Some(proof_statement_hash) = package["proofStatementHash"]
        .as_str()
        .map(ToString::to_string)
    {
        package["signature"]["proofStatementHash"] = json!(proof_statement_hash);
    }
}
