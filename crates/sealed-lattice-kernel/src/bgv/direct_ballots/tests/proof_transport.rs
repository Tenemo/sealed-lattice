use super::*;

use crate::protocol_signatures::create_protocol_signature_fixture;

const DIRECT_BALLOT_VOTER_SIGNATURE_FIXTURE_SEED: &str =
    "direct-encrypted-ballot-voter-signature-fixture";

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
    assert_eq!(transport.encrypted_ballot_package["signature"], Value::Null);
    assert_eq!(
        transport.voter_signature_signed_root["objectRoot"].as_str(),
        Some(transport.encrypted_ballot_package_root.as_str())
    );
    assert_eq!(
        transport.voter_signature_signed_root["contextHash"].as_str(),
        Some(fixture.encrypted_ballot.input.action_context_hash.as_str())
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
        (
            fixture.proof_generation.proof_size_bytes,
            transport.proof_size_bytes,
            transport.chunk_count,
            fixture.proof_generation.statement_hash_hex.as_str(),
            fixture.proof_generation.proof_bytes_hash.as_str(),
            transport.proof_chunk_manifest_root.as_str(),
            transport.encrypted_ballot_package_root.as_str(),
        ),
        (
            48_154_664,
            48_154_664,
            46,
            "4c0101bb5b819f5b9f08a45029dfb2e5282e51f95815ac6c373bc8567c7f027273466252977ba0f52a45ff1a63069c750f2b505d81d7a3ba469b96aa833ec36b",
            "191c264e5661e2f55e23b5c72cee10a894cc482d5b4ce106bdf25f4c5967357bd7e293d07d1c3ce751d5d055fde0d44a4333505cc49e0567c61c28ab625d79eb",
            "8e940a71492f470170148febfc64eb87a83263c2110c40ff5953371afc9a58cd6b23939a9477347aa27325239bf5ed7abdb810b4191798fdd07442ca9291f673",
            "e64d711211e61dedf9375d392e1e251b425bad5e9ab958415a216873230ed3643620aac99f586167d61a8ff81e37062abf3044796f6c4ca03dccedbaa79bdaff",
        )
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
    let (package, voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);

    let result = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
        "encryptedBallotPackage": package,
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
            "setup handoff, voter signature, public package artifacts, verifier-certified proof profile, and direct ballot relation proof verified"
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
    assert_eq!(
        result["signatureStatus"].as_str(),
        Some(
            "voter ML-DSA protocol signature verified against the supplied voter signing public-key hash and encrypted ballot package root"
        )
    );
    let certificate = &result["packageVerificationCertificate"];
    assert_eq!(
        certificate["objectType"].as_str(),
        Some("DirectEncryptedBallotPackageVerificationCertificate")
    );
    assert_eq!(certificate["packageRoot"], result["packageRoot"]);
    assert_eq!(certificate["signatureHash"], result["signatureHash"]);
    assert_eq!(
        certificate["publicAggregationInput"]["packageRoot"],
        result["packageRoot"]
    );
    assert_eq!(
        certificate["publicAggregationInput"]["ciphertextRoot"],
        result["ciphertextRoot"]
    );
    assert_eq!(
        certificate["packageVerificationCertificateHash"],
        result["packageVerificationCertificateHash"]
    );
    let mut certificate_hash_input = certificate.clone();
    certificate_hash_input
        .as_object_mut()
        .expect("certificate object")
        .remove("packageVerificationCertificateHash");
    let expected_certificate_hash = derive_protocol_hash(
        "DirectEncryptedBallotPackageVerificationCertificateHash",
        &certificate_hash_input,
    )
    .expect("certificate hash");
    assert_eq!(
        result["packageVerificationCertificateHash"].as_str(),
        Some(expected_certificate_hash.as_str())
    );
    assert!(
        result["claimBoundary"]
            .as_str()
            .expect("claim boundary")
            .contains("cannot recover consumed randomness")
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
    let (package, voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);
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
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
        "encryptedBallotPackage": package,
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
    let (mut package, voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);
    package["plaintextScores"] = json!([1, 2, 3]);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
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
    let voter_signing_public_key_hash = sign_encrypted_ballot_package(&mut package);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
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
    let voter_signing_public_key_hash = sign_encrypted_ballot_package(&mut package);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
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
        "soundnessCertificateHash",
        "zeroKnowledgeCertificateHash",
        "verifierCertificateHash",
    ] {
        let mut package = transport.encrypted_ballot_package.clone();
        package[field_name] = json!("0".repeat(128));
        rebind_encrypted_ballot_package_root(&mut package);
        let voter_signing_public_key_hash = sign_encrypted_ballot_package(&mut package);

        let error = verify_direct_encrypted_ballot_package(&json!({
            "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
            "acceptedSetupHandoff": fixture.accepted_setup_handoff,
            "voterSigningPublicKeyHash": voter_signing_public_key_hash,
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
    let voter_signing_public_key_hash = sign_encrypted_ballot_package(&mut package);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
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
    let (package, voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);
    let mut proof_chunks = transport.proof_chunks.clone();
    proof_chunks[0]["legacyBytes"] = json!("00");

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
        "encryptedBallotPackage": package,
        "proofChunks": proof_chunks,
    }))
    .expect_err("proof chunk with an unexpected field must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("proofChunks[0]"));
    assert!(error.message.contains("unexpected field legacyBytes"));
}

#[test]
fn direct_ballot_package_verifier_rejects_unsigned_package() {
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
    let (_, voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
        "encryptedBallotPackage": transport.encrypted_ballot_package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("unsigned package must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("signature"));
}

#[test]
fn direct_ballot_package_verifier_rejects_wrong_voter_signing_key() {
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
    let (package, _voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": "0".repeat(128),
        "encryptedBallotPackage": package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("signature under a different expected voter key must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("expected key"));
}

#[test]
fn direct_ballot_package_verifier_rejects_tampered_voter_signature_bytes() {
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
    let (mut package, voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);
    let signature_bytes_hex = package["signature"]["signatureBytesHex"]
        .as_str()
        .expect("signature bytes hex");
    let replacement_prefix = if signature_bytes_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    package["signature"]["signatureBytesHex"] =
        json!(format!("{replacement_prefix}{}", &signature_bytes_hex[1..]));

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": fixture.accepted_public_key_material,
        "acceptedSetupHandoff": fixture.accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
        "encryptedBallotPackage": package,
        "proofChunks": transport.proof_chunks,
    }))
    .expect_err("tampered voter signature bytes must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("ML-DSA signature"));
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
    let (package, voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);
    let mut accepted_setup_handoff = fixture.accepted_setup_handoff.clone();
    accepted_setup_handoff["setupPackageHash"] = json!("0".repeat(128));
    rebind_accepted_setup_handoff_root(&mut accepted_setup_handoff);
    let mut accepted_public_key_material = fixture.accepted_public_key_material.clone();
    accepted_public_key_material["acceptedSetupHandoffRoot"] =
        accepted_setup_handoff["acceptedSetupHandoffRoot"].clone();

    let error = verify_direct_encrypted_ballot_package(&json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material,
        "acceptedSetupHandoff": accepted_setup_handoff,
        "voterSigningPublicKeyHash": voter_signing_public_key_hash,
        "encryptedBallotPackage": package,
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
    let (package, voter_signing_public_key_hash) = signed_encrypted_ballot_package(&transport);

    for field_name in [
        "batchLayoutBindingHash",
        "ballotScoreEncodingProfileHash",
        "encryptedBallotLayoutHash",
        "directBallotReservedSlotRuleHash",
        "directBallotEncoderMatrixRoot",
        "witnessPartitionProfileHash",
        "arithmeticCertificateHash",
        "soundnessCertificateHash",
        "zeroKnowledgeCertificateHash",
        "verifierCertificateHash",
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
            "voterSigningPublicKeyHash": voter_signing_public_key_hash,
            "encryptedBallotPackage": package,
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

#[test]
fn direct_ballot_proof_chunk_manifest_rejects_proof_profile_tampering() {
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
    tampered_manifest["proofProfileHash"] = json!("0".repeat(128));

    let error =
        verify_direct_ballot_proof_chunk_manifest(&tampered_manifest, &transport.proof_bytes)
            .expect_err("tampered proof profile hash must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("proofProfileHash"));
}

fn rebind_encrypted_ballot_package_root(package: &mut Value) {
    let package_object = package
        .as_object()
        .expect("encrypted ballot package object")
        .clone();
    let mut unsigned_package = package_object;
    unsigned_package.remove("packageRoot");
    unsigned_package.remove("signature");
    let package_root = derive_protocol_hash(
        "EncryptedBallotPackageRoot",
        &Value::Object(unsigned_package),
    )
    .expect("package root");
    package["packageRoot"] = json!(package_root);
    package["signature"] = Value::Null;
}

fn signed_encrypted_ballot_package(
    transport: &DirectBallotBinaryProofTransport,
) -> (Value, String) {
    let mut package = transport.encrypted_ballot_package.clone();
    let voter_signing_public_key_hash = sign_encrypted_ballot_package(&mut package);

    (package, voter_signing_public_key_hash)
}

fn sign_encrypted_ballot_package(package: &mut Value) -> String {
    let signed_root =
        encrypted_ballot_package_voter_signature_signed_root(package).expect("signed root");
    let voter_identity = package["voterIdentity"]
        .as_str()
        .expect("voter identity in package");
    let signature_fixture = create_protocol_signature_fixture(
        &format!("{DIRECT_BALLOT_VOTER_SIGNATURE_FIXTURE_SEED}-{voter_identity}"),
        signed_root,
    )
    .expect("voter signature fixture");
    package["signature"] = signature_fixture.envelope;

    signature_fixture.public_key_hash
}
