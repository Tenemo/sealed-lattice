use super::*;

const ENCRYPTED_BALLOT_PACKAGE_FIELDS: &[&str] = &[
    "objectType",
    "objectVersion",
    "ceremonyId",
    "manifestHash",
    "rosterHash",
    "thresholdProfileHash",
    "setupPackageRoot",
    "setupProfileHash",
    "voterIdentity",
    "voterRosterPosition",
    "actionContextHash",
    "recoveryEpoch",
    "deviceEpoch",
    "bgvProfileHash",
    "batchEncoderHash",
    "batchLayoutBindingHash",
    "ballotScoreEncodingProfileHash",
    "encryptedBallotLayoutHash",
    "directBallotReservedSlotRuleHash",
    "directBallotEncoderMatrixRoot",
    "collectivePublicKeyRoot",
    "bgvPublicKeyRoot",
    "ciphertextRoot",
    "ciphertextTransport",
    "witnessPartitionProfileHash",
    "arithmeticCertificateHash",
    "proofProfileHash",
    "proofStatementHash",
    "proofChunkManifest",
    "proofFullBytesHash",
    "proofChunkRoot",
    "packageRoot",
    "signature",
];

const ENCRYPTED_BALLOT_CIPHERTEXT_TRANSPORT_FIELDS: &[&str] = &[
    "encoding",
    "canonicalByteLength",
    "canonicalBytesHex",
    "ciphertextRoot",
    "ciphertextLimbRoots",
];

const DIRECT_BALLOT_PUBLIC_PROOF_CHUNK_FIELDS: &[&str] =
    &["chunkIndex", "byteLength", "chunkHash", "bytesHex"];

const DEVELOPMENT_SIGNATURE_PLACEHOLDER_FIELDS: &[&str] = &[
    "objectType",
    "objectVersion",
    "status",
    "expectedSignerRole",
    "signedObjectRoot",
    "voterIdentity",
    "voterRosterPosition",
    "contextHash",
    "setupPackageRoot",
    "ciphertextRoot",
    "proofStatementHash",
    "proofChunkRoot",
];

pub(crate) fn verify_direct_encrypted_ballot_package(request: &Value) -> CanonicalResult<Value> {
    reject_package_verifier_private_fields(request)?;
    let accepted_public_key_material = required_object_field(request, "acceptedPublicKeyMaterial")?;
    let accepted_setup_handoff = required_object_field(request, "acceptedSetupHandoff")?;
    let accepted_setup_handoff_root =
        validate_direct_ballot_setup_handoff(accepted_public_key_material, accepted_setup_handoff)?;
    let package = required_object_field(request, "encryptedBallotPackage")?;
    reject_forbidden_package_fields(package)?;
    reject_unexpected_direct_ballot_object_fields(
        package,
        "encryptedBallotPackage",
        ENCRYPTED_BALLOT_PACKAGE_FIELDS,
    )?;
    verify_direct_ballot_package_type(package)?;
    let package_root = verify_direct_ballot_package_root(package)?;
    verify_development_signature_placeholder(package, &package_root)?;
    let proof_manifest = required_object_field(package, "proofChunkManifest")?;
    let proof_chunk_root = verify_package_proof_manifest_root(package, proof_manifest)?;
    let proof_bytes = read_ordered_public_proof_chunks(request, proof_manifest)?;
    verify_direct_ballot_proof_chunk_manifest(proof_manifest, &proof_bytes)?;

    let public_key =
        public_bgv_key_from_accepted_setup_public_key_material(accepted_public_key_material)?;
    let ballot = direct_ballot_from_public_package(accepted_public_key_material, package)?;
    let proof_statement =
        direct_ballot_validity_statement(accepted_public_key_material, &public_key, &ballot)?;
    verify_package_statement_binding(package, proof_manifest, &proof_statement)?;
    let proof_verification = verify_direct_ballot_relation_proof(
        accepted_public_key_material,
        &public_key,
        &ballot,
        &proof_bytes,
    )?;

    Ok(json!({
        "operation": VERIFY_DIRECT_BALLOT_PACKAGE_OPERATION,
        "verificationStatus": "setup handoff, public package artifacts, and internal direct ballot relation proof verified",
        "acceptedSetupHandoffRoot": accepted_setup_handoff_root,
        "packageRoot": package_root,
        "ciphertextRoot": ballot.ciphertext_root,
        "proofStatementHash": proof_statement.hash_hex,
        "verifiedStatementHash": proof_verification.statement_hash_hex,
        "proofBytesHash": direct_ballot_relation_proof_bytes_hash(&proof_bytes),
        "proofChunkRoot": proof_chunk_root,
        "proofSizeBytes": proof_verification.proof_size_bytes,
        "proofChunkCount": required_usize_field(proof_manifest, "chunkCount")?,
        "relationCommitmentHash": proof_verification.relation_commitment_hash_hex,
        "challenge": proof_verification.challenge,
        "signatureStatus": "development package signature placeholder checked for root and action-context binding; no voter signature verification is accepted yet",
        "claimBoundary": "Accepted public-key material is checked against the accepted setup handoff, and package structure, canonical ciphertext bytes, proof chunk manifest, public proof chunks, statement binding, the projected response transcript, and the appended committed trace proof are verified from public artifacts. This remains development evidence because signature verification, soundness, zero-knowledge, and Fiat-Shamir/QROM accounting are not closed.",
    }))
}

struct DirectBallotPublicProofChunk {
    chunk_index: usize,
    bytes: Vec<u8>,
    chunk_hash: String,
}

fn reject_package_verifier_private_fields(request: &Value) -> CanonicalResult<()> {
    for field_name in [
        "setupPackage",
        "setupPublicMaterial",
        "setupPrivateWitness",
        "ballotEncryptionRandomness",
        "proofMaskRandomness",
        "topCount",
        "topCounts",
        "publicEvaluationKeyMaterial",
        "targetFinalityPolicyHash",
    ] {
        if request.get(field_name).is_some() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("verifyDirectEncryptedBallotPackage does not accept {field_name}"),
            ));
        }
    }

    Ok(())
}

fn verify_direct_ballot_package_type(package: &Value) -> CanonicalResult<()> {
    if package.get("objectType").and_then(Value::as_str) != Some("EncryptedBallotPackage") {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectType,
            "encrypted ballot package must be an EncryptedBallotPackage",
        ));
    }
    if package.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "encrypted ballot package has an unsupported version",
        ));
    }

    Ok(())
}

fn verify_direct_ballot_package_root(package: &Value) -> CanonicalResult<String> {
    let package_root = required_string_field(package, "packageRoot")?;
    validate_direct_ballot_hash_hex(package_root, "encryptedBallotPackage.packageRoot")?;
    let mut unsigned_package = package
        .as_object()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "encrypted ballot package must be an object",
            )
        })?
        .clone();
    unsigned_package.remove("packageRoot");
    unsigned_package.remove("signature");
    let recomputed_package_root = derive_protocol_hash(
        "EncryptedBallotPackageRoot",
        &Value::Object(unsigned_package),
    )?;
    if recomputed_package_root != package_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package root does not match its public fields",
        ));
    }

    Ok(package_root.to_string())
}

fn verify_development_signature_placeholder(
    package: &Value,
    package_root: &str,
) -> CanonicalResult<()> {
    let signature = required_object_field(package, "signature")?;
    reject_unexpected_direct_ballot_object_fields(
        signature,
        "encryptedBallotPackage.signature",
        DEVELOPMENT_SIGNATURE_PLACEHOLDER_FIELDS,
    )?;
    if required_string_field(signature, "objectType")?
        != "DevelopmentEncryptedBallotPackageSignaturePlaceholder"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectType,
            "encrypted ballot package signature placeholder has an unsupported object type",
        ));
    }
    if signature.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "encrypted ballot package signature placeholder has an unsupported version",
        ));
    }
    if required_string_field(signature, "status")?
        != "not supplied in the internal development command"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "development encrypted ballot package verifier does not accept an unverified signature object",
        ));
    }
    if required_string_field(signature, "signedObjectRoot")? != package_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package signature placeholder does not bind the package root",
        ));
    }
    for (signature_field_name, package_field_name) in [
        ("voterIdentity", "voterIdentity"),
        ("voterRosterPosition", "voterRosterPosition"),
        ("contextHash", "actionContextHash"),
        ("setupPackageRoot", "setupPackageRoot"),
        ("ciphertextRoot", "ciphertextRoot"),
        ("proofStatementHash", "proofStatementHash"),
        ("proofChunkRoot", "proofChunkRoot"),
    ] {
        if signature.get(signature_field_name) != package.get(package_field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "encrypted ballot package signature placeholder does not bind {package_field_name}"
                ),
            ));
        }
    }

    Ok(())
}

fn verify_package_proof_manifest_root(
    package: &Value,
    proof_manifest: &Value,
) -> CanonicalResult<String> {
    let proof_chunk_root = required_string_field(package, "proofChunkRoot")?;
    validate_direct_ballot_hash_hex(proof_chunk_root, "encryptedBallotPackage.proofChunkRoot")?;
    let recomputed_proof_chunk_root =
        derive_protocol_hash("BallotProofChunkManifestRoot", proof_manifest)?;
    if recomputed_proof_chunk_root != proof_chunk_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package proof chunk root does not match its manifest",
        ));
    }

    Ok(proof_chunk_root.to_string())
}

fn read_ordered_public_proof_chunks(
    request: &Value,
    proof_manifest: &Value,
) -> CanonicalResult<Vec<u8>> {
    let proof_chunk_values = request
        .get("proofChunks")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "proofChunks must be an array",
            )
        })?;
    let expected_chunk_count = required_usize_field(proof_manifest, "chunkCount")?;
    if proof_chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proofChunks length does not match the proof chunk manifest",
        ));
    }
    let expected_proof_byte_length = required_usize_field(proof_manifest, "proofByteLength")?;
    let expected_chunk_size_bytes = required_usize_field(proof_manifest, "chunkSizeBytes")?;
    let expected_proof_bytes_hash = required_string_field(proof_manifest, "proofFullBytesHash")?;
    let expected_chunk_hashes = required_string_array_field(proof_manifest, "chunkHashList")?;
    if expected_chunk_hashes.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proof chunk manifest hash list length does not match chunk count",
        ));
    }

    let mut parsed_chunks = Vec::with_capacity(expected_chunk_count);
    let mut proof_byte_length = 0_usize;
    for (expected_chunk_index, proof_chunk_value) in proof_chunk_values.iter().enumerate() {
        let proof_chunk = required_public_proof_chunk(proof_chunk_value, expected_chunk_index)?;
        if proof_chunk.chunk_index + 1 < expected_chunk_count
            && proof_chunk.bytes.len() != expected_chunk_size_bytes
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "proofChunks contains a short non-final chunk",
            ));
        }
        if proof_chunk.bytes.len() > expected_chunk_size_bytes {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "proofChunks contains a chunk larger than the manifest chunk size",
            ));
        }
        let expected_chunk_hash = &expected_chunk_hashes[expected_chunk_index];
        if proof_chunk.chunk_hash != *expected_chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "proofChunks[{expected_chunk_index}].chunkHash does not match the proof chunk manifest"
                ),
            ));
        }
        let recomputed_chunk_hash = direct_ballot_proof_chunk_hash(
            expected_proof_bytes_hash,
            expected_chunk_index,
            &proof_chunk.bytes,
        )?;
        if recomputed_chunk_hash != proof_chunk.chunk_hash {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("proofChunks[{expected_chunk_index}] bytes do not match chunkHash"),
            ));
        }
        proof_byte_length = proof_byte_length
            .checked_add(proof_chunk.bytes.len())
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "proofChunks byte length overflowed",
                )
            })?;
        parsed_chunks.push(proof_chunk);
    }
    if proof_byte_length != expected_proof_byte_length {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proofChunks byte length does not match the proof chunk manifest",
        ));
    }

    let mut proof_bytes = Vec::with_capacity(expected_proof_byte_length);
    for proof_chunk in parsed_chunks {
        proof_bytes.extend_from_slice(&proof_chunk.bytes);
    }

    Ok(proof_bytes)
}

fn required_public_proof_chunk(
    proof_chunk_value: &Value,
    expected_chunk_index: usize,
) -> CanonicalResult<DirectBallotPublicProofChunk> {
    reject_unexpected_direct_ballot_object_fields(
        proof_chunk_value,
        &format!("proofChunks[{expected_chunk_index}]"),
        DIRECT_BALLOT_PUBLIC_PROOF_CHUNK_FIELDS,
    )?;
    let chunk_index = required_usize_field(proof_chunk_value, "chunkIndex")?;
    if chunk_index != expected_chunk_index {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "proofChunks must be supplied in strict chunkIndex order",
        ));
    }
    let bytes_hex = required_string_field(proof_chunk_value, "bytesHex")?;
    let bytes = crate::transcript_core::decode_hex(bytes_hex)?;
    let byte_length = required_usize_field(proof_chunk_value, "byteLength")?;
    if byte_length != bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proofChunks[].byteLength does not match bytesHex",
        ));
    }
    if bytes.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proofChunks entries must not be empty",
        ));
    }
    let chunk_hash = required_string_field(proof_chunk_value, "chunkHash")?;
    validate_direct_ballot_hash_hex(chunk_hash, "proofChunks[].chunkHash")?;

    Ok(DirectBallotPublicProofChunk {
        chunk_index,
        bytes,
        chunk_hash: chunk_hash.to_string(),
    })
}

fn direct_ballot_from_public_package(
    setup_package: &Value,
    package: &Value,
) -> CanonicalResult<DirectEncryptedBallot> {
    let ciphertext_root = required_string_field(package, "ciphertextRoot")?.to_string();
    validate_direct_ballot_hash_hex(&ciphertext_root, "encryptedBallotPackage.ciphertextRoot")?;
    let ciphertext_transport = required_object_field(package, "ciphertextTransport")?;
    reject_unexpected_direct_ballot_object_fields(
        ciphertext_transport,
        "encryptedBallotPackage.ciphertextTransport",
        ENCRYPTED_BALLOT_CIPHERTEXT_TRANSPORT_FIELDS,
    )?;
    if required_string_field(ciphertext_transport, "encoding")?
        != "sealed-lattice-bgv-rns-canonical-ciphertext-v1"
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidEnum,
            "encrypted ballot package ciphertext transport encoding is not supported",
        ));
    }
    if required_string_field(ciphertext_transport, "ciphertextRoot")? != ciphertext_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package ciphertext transport root does not match package root",
        ));
    }
    let ciphertext_canonical_bytes_hex =
        required_string_field(ciphertext_transport, "canonicalBytesHex")?;
    crate::bgv::validation::validate_ciphertext_hex(
        ciphertext_canonical_bytes_hex,
        Some(&ciphertext_root),
    )?;
    let ciphertext_canonical_byte_length = ciphertext_canonical_bytes_hex.len() / 2;
    if required_usize_field(ciphertext_transport, "canonicalByteLength")?
        != ciphertext_canonical_byte_length
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted ballot package ciphertext canonical byte length does not match canonicalBytesHex",
        ));
    }
    let canonical_ciphertext =
        crate::bgv::serialization::parse_bgv_object_hex(ciphertext_canonical_bytes_hex)?;
    if canonical_ciphertext.object_kind != crate::bgv::serialization::BgvObjectKind::Ciphertext {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "encrypted ballot package ciphertext transport is not a ciphertext",
        ));
    }
    if canonical_ciphertext.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "encrypted ballot package ciphertext must have two components",
        ));
    }
    let mut ciphertext_components = Vec::with_capacity(canonical_ciphertext.components.len());
    for component in canonical_ciphertext.components {
        if component.level != DATA_PRIMES.len() - 1 || component.moduli != DATA_PRIMES {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                "encrypted ballot package ciphertext does not use the full data-prime basis",
            ));
        }
        ciphertext_components.push(component.residues_by_modulus);
    }
    let ballot_input = DirectBallotInput {
        voter_identity: required_string_field(package, "voterIdentity")?.to_string(),
        voter_roster_position: required_usize_field(package, "voterRosterPosition")?,
        action_context_hash: required_string_field(package, "actionContextHash")?.to_string(),
        recovery_epoch: required_u64_field(package, "recoveryEpoch")?,
        device_epoch: required_u64_field(package, "deviceEpoch")?,
        scores: Vec::new(),
        one_hot_witnesses: None,
        encryption_seed_hex: String::new(),
    };
    validate_direct_ballot_hash_hex(&ballot_input.action_context_hash, "actionContextHash")?;
    let encrypted_ballot_hash = direct_encrypted_ballot_hash(
        setup_package,
        &ballot_input,
        &ciphertext_root,
        ciphertext_canonical_byte_length,
    )?;
    let ballot = DirectEncryptedBallot {
        input: ballot_input,
        slots: Vec::new(),
        plaintext_coefficients: Vec::new(),
        ciphertext: Ciphertext {
            components: ciphertext_components,
            level: DATA_PRIMES.len() - 1,
            decrypt_scaling: 1,
        },
        encryption_witness: EncryptionWitness {
            randomizer_coefficients: Vec::new(),
            error_zero_coefficients: Vec::new(),
            error_one_coefficients: Vec::new(),
        },
        encrypted_ballot_hash,
        ciphertext_root,
        ciphertext_canonical_byte_length,
    };
    let expected_limb_roots = Value::Array(direct_ballot_ciphertext_limb_roots(&ballot)?);
    if ciphertext_transport.get("ciphertextLimbRoots") != Some(&expected_limb_roots) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package ciphertext limb roots do not match canonical ciphertext bytes",
        ));
    }

    Ok(ballot)
}

fn verify_package_statement_binding(
    package: &Value,
    proof_manifest: &Value,
    proof_statement: &DirectBallotValidityStatement,
) -> CanonicalResult<()> {
    if required_string_field(package, "proofStatementHash")? != proof_statement.hash_hex {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package proofStatementHash does not match the rebuilt statement",
        ));
    }
    if required_string_field(proof_manifest, "statementHash")? != proof_statement.hash_hex {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package proof manifest statementHash does not match the rebuilt statement",
        ));
    }
    let proof_profile_hash = required_string_field(&proof_statement.value, "proofProfileHash")?;
    if required_string_field(package, "proofProfileHash")? != proof_profile_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package proof profile hash does not match the rebuilt statement",
        ));
    }
    for field_name in [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "thresholdProfileHash",
        "setupPackageRoot",
        "setupProfileHash",
        "voterIdentity",
        "voterRosterPosition",
        "actionContextHash",
        "collectivePublicKeyRoot",
        "bgvPublicKeyRoot",
        "bgvProfileHash",
        "batchEncoderHash",
        "batchLayoutBindingHash",
        "ballotScoreEncodingProfileHash",
        "encryptedBallotLayoutHash",
        "directBallotReservedSlotRuleHash",
        "directBallotEncoderMatrixRoot",
        "ciphertextRoot",
        "witnessPartitionProfileHash",
        "arithmeticCertificateHash",
        "proofProfileHash",
    ] {
        if package.get(field_name) != proof_statement.value.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "encrypted ballot package {field_name} does not match the rebuilt statement"
                ),
            ));
        }
    }
    for field_name in [
        "voterIdentity",
        "voterRosterPosition",
        "actionContextHash",
        "setupPackageRoot",
        "ciphertextRoot",
        "proofProfileHash",
    ] {
        if package.get(field_name) != proof_manifest.get(field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!(
                    "encrypted ballot package {field_name} does not match proof chunk manifest"
                ),
            ));
        }
    }
    if required_string_field(package, "proofFullBytesHash")?
        != required_string_field(proof_manifest, "proofFullBytesHash")?
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted ballot package proofFullBytesHash does not match proof chunk manifest",
        ));
    }

    Ok(())
}

fn reject_forbidden_package_fields(package: &Value) -> CanonicalResult<()> {
    for field_name in [
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
        if value_contains_object_field(package, field_name) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("encrypted ballot package must not contain {field_name}"),
            ));
        }
    }

    Ok(())
}

fn value_contains_object_field(value: &Value, field_name: &str) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, child)| {
            key == field_name || value_contains_object_field(child, field_name)
        }),
        Value::Array(array) => array
            .iter()
            .any(|child| value_contains_object_field(child, field_name)),
        _ => false,
    }
}
