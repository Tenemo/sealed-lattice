use super::*;

const ENCRYPTED_BALLOT_PACKAGE_OBJECT_TYPE: &str = "EncryptedBallotPackage";
const ENCRYPTED_BALLOT_PACKAGE_OBJECT_VERSION: u64 = 1;
const BALLOT_VALIDITY_STATEMENT_ID: &str = "BallotValidityStatement-v1";
const BALLOT_PROOF_CHUNK_MANIFEST_OBJECT_TYPE: &str = "BallotProofChunkManifest";
const BALLOT_PROOF_CHUNK_MANIFEST_OBJECT_VERSION: u64 = 1;
const BALLOT_PROOF_CHUNK_MANIFEST_FIELDS: &[&str] = &[
    "objectType",
    "objectVersion",
    "proofByteLength",
    "chunkSizeBytes",
    "chunkCount",
    "chunkHashList",
    "chunkMerkleRoot",
    "proofFullBytesHash",
    "statementHash",
    "ciphertextRoot",
    "voterIdentity",
    "voterRosterPosition",
    "actionContextHash",
    "setupPackageRoot",
    "proofProfileHash",
];
const DIRECT_BALLOT_STATEMENT_BINARY_MAGIC: &str = "sealed-lattice-ballot-validity-statement";
const DIRECT_BALLOT_CIPHERTEXT_LIMB_ROOT_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/ciphertext-limb-root-v1";
const DIRECT_BALLOT_PUBLIC_KEY_LIMB_ROOT_DOMAIN: &str =
    "sealed-lattice/direct-encrypted-ballot/public-key-limb-root-v1";

pub(super) struct DirectBallotValidityStatement {
    pub(super) hash: [u8; 64],
    pub(super) hash_hex: String,
    pub(super) value: Value,
}

pub(super) struct DirectBallotProofChunkManifest {
    pub(super) root: String,
    pub(super) value: Value,
}

pub(super) struct DirectBallotEncryptedPackage {
    pub(super) root: String,
    pub(super) value: Value,
    pub(super) voter_signature_signed_root: Value,
}

pub(super) fn direct_ballot_validity_statement(
    setup_package: &Value,
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<DirectBallotValidityStatement> {
    let setup_context = direct_ballot_setup_context(setup_package)?;
    let profile_binding = direct_ballot_profile_binding(setup_package)?;
    let proof_profile_hash = direct_ballot_relation_proof_profile_hash()?;
    let witness_partition_profile_hash = direct_ballot_witness_partition_profile_hash()?;
    let arithmetic_certificate_hash = direct_ballot_arithmetic_certificate_hash()?;
    let soundness_certificate_hash = direct_ballot_soundness_certificate_hash()?;
    let zero_knowledge_certificate_hash = direct_ballot_zero_knowledge_certificate_hash()?;
    let verifier_certificate_hash = profile_binding.verifier_certificate_hash.clone();
    let ciphertext_limb_roots = direct_ballot_ciphertext_limb_roots(ballot)?;
    let public_key_limb_roots = direct_ballot_public_key_limb_roots(public_key)?;
    let canonical_bytes =
        direct_ballot_validity_statement_bytes(DirectBallotValidityStatementBytesInput {
            setup_context: &setup_context,
            profile_binding: &profile_binding,
            ballot,
            proof_profile_hash: &proof_profile_hash,
            witness_partition_profile_hash: &witness_partition_profile_hash,
            arithmetic_certificate_hash: &arithmetic_certificate_hash,
            soundness_certificate_hash: &soundness_certificate_hash,
            zero_knowledge_certificate_hash: &zero_knowledge_certificate_hash,
            verifier_certificate_hash: &verifier_certificate_hash,
            ciphertext_limb_roots: &ciphertext_limb_roots,
            public_key_limb_roots: &public_key_limb_roots,
        })?;
    let hash = hash512(
        BALLOT_VALIDITY_STATEMENT_HASH_NAMESPACE,
        &[canonical_bytes.as_slice()],
    );
    let hash_hex = to_hex(&hash);
    let value = json!({
        "statementId": BALLOT_VALIDITY_STATEMENT_ID,
        "objectVersion": 1,
        "statementEncoding": "canonical-binary-length-delimited-v1",
        "statementHash": hash_hex,
        "canonicalByteLength": canonical_bytes.len(),
        "ceremonyId": setup_context.ceremony_id,
        "manifestHash": setup_context.manifest_hash,
        "rosterHash": setup_context.roster_hash,
        "thresholdProfileHash": setup_context.threshold_profile_hash,
        "setupPackageRoot": setup_context.setup_package_root,
        "setupProfileHash": setup_context.setup_profile_hash,
        "voterIdentity": ballot.input.voter_identity.as_str(),
        "voterRosterPosition": ballot.input.voter_roster_position,
        "actionContextHash": ballot.input.action_context_hash.as_str(),
        "collectivePublicKeyRoot": setup_context.collective_public_key_root,
        "bgvPublicKeyRoot": setup_context.bgv_public_key_root,
        "bgvProfileHash": profile_binding.bgv_profile_hash,
        "batchEncoderHash": profile_binding.batch_encoder_hash,
        "batchLayoutBindingHash": profile_binding.batch_layout_binding_hash,
        "ballotScoreEncodingProfileHash": profile_binding.ballot_score_encoding_profile_hash,
        "encryptedBallotLayoutHash": profile_binding.encrypted_ballot_layout_hash,
        "directBallotReservedSlotRuleHash": profile_binding.direct_ballot_reserved_slot_rule_hash,
        "directBallotEncoderMatrixRoot": profile_binding.direct_ballot_encoder_matrix_root,
        "ciphertextRoot": ballot.ciphertext_root.as_str(),
        "witnessPartitionProfileHash": witness_partition_profile_hash,
        "arithmeticCertificateHash": arithmetic_certificate_hash,
        "soundnessCertificateHash": soundness_certificate_hash,
        "zeroKnowledgeCertificateHash": zero_knowledge_certificate_hash,
        "verifierCertificateHash": verifier_certificate_hash,
        "proofProfileHash": proof_profile_hash,
        "ciphertextLimbRoots": ciphertext_limb_roots,
        "publicKeyLimbRoots": public_key_limb_roots,
    });

    Ok(DirectBallotValidityStatement {
        hash,
        hash_hex,
        value,
    })
}

pub(super) fn direct_ballot_validity_statement_hash(
    setup_package: &Value,
    public_key: &BgvPublicKey,
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<[u8; 64]> {
    direct_ballot_validity_statement(setup_package, public_key, ballot)
        .map(|statement| statement.hash)
}

pub(super) struct DirectBallotProofChunkManifestInput<'a> {
    pub(super) setup_package: &'a Value,
    pub(super) ballot: &'a DirectEncryptedBallot,
    pub(super) proof_statement_hash: &'a str,
    pub(super) proof_full_bytes_hash: &'a str,
    pub(super) proof_byte_length: usize,
    pub(super) chunk_size_bytes: usize,
    pub(super) chunk_count: usize,
    pub(super) chunk_hashes: &'a [String],
    pub(super) chunk_merkle_root: &'a str,
}

pub(super) fn direct_ballot_proof_chunk_manifest(
    input: DirectBallotProofChunkManifestInput<'_>,
) -> CanonicalResult<DirectBallotProofChunkManifest> {
    validate_direct_ballot_hash_hex(input.proof_statement_hash, "proofStatementHash")?;
    validate_direct_ballot_hash_hex(input.proof_full_bytes_hash, "proofFullBytesHash")?;
    validate_direct_ballot_hash_hex(input.chunk_merkle_root, "proofChunkRoot")?;
    for (chunk_index, chunk_hash) in input.chunk_hashes.iter().enumerate() {
        validate_direct_ballot_hash_hex(
            chunk_hash,
            &format!("proofChunkManifest.chunkHashList[{chunk_index}]"),
        )?;
    }
    let setup_context = direct_ballot_setup_context(input.setup_package)?;
    let proof_profile_hash = direct_ballot_relation_proof_profile_hash()?;
    let manifest = json!({
        "objectType": BALLOT_PROOF_CHUNK_MANIFEST_OBJECT_TYPE,
        "objectVersion": BALLOT_PROOF_CHUNK_MANIFEST_OBJECT_VERSION,
        "proofByteLength": input.proof_byte_length,
        "chunkSizeBytes": input.chunk_size_bytes,
        "chunkCount": input.chunk_count,
        "chunkHashList": input.chunk_hashes,
        "chunkMerkleRoot": input.chunk_merkle_root,
        "proofFullBytesHash": input.proof_full_bytes_hash,
        "statementHash": input.proof_statement_hash,
        "ciphertextRoot": input.ballot.ciphertext_root.as_str(),
        "voterIdentity": input.ballot.input.voter_identity.as_str(),
        "voterRosterPosition": input.ballot.input.voter_roster_position,
        "actionContextHash": input.ballot.input.action_context_hash.as_str(),
        "setupPackageRoot": setup_context.setup_package_root,
        "proofProfileHash": proof_profile_hash,
    });
    let root = derive_protocol_hash("BallotProofChunkManifestRoot", &manifest)?;

    Ok(DirectBallotProofChunkManifest {
        root,
        value: manifest,
    })
}

pub(super) fn verify_direct_ballot_proof_chunk_manifest(
    manifest: &Value,
    proof_bytes: &[u8],
) -> CanonicalResult<()> {
    reject_unexpected_direct_ballot_object_fields(
        manifest,
        "proofChunkManifest",
        BALLOT_PROOF_CHUNK_MANIFEST_FIELDS,
    )?;
    if manifest.get("objectType").and_then(Value::as_str)
        != Some(BALLOT_PROOF_CHUNK_MANIFEST_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectType,
            "proof chunk manifest must be a BallotProofChunkManifest",
        ));
    }
    if manifest.get("objectVersion").and_then(Value::as_u64)
        != Some(BALLOT_PROOF_CHUNK_MANIFEST_OBJECT_VERSION)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "proof chunk manifest has an unsupported version",
        ));
    }
    let proof_byte_length = required_usize_field(manifest, "proofByteLength")?;
    if proof_byte_length != proof_bytes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proof chunk manifest byte length does not match proof bytes",
        ));
    }
    let chunk_size_bytes = required_usize_field(manifest, "chunkSizeBytes")?;
    let chunk_count = required_usize_field(manifest, "chunkCount")?;
    let expected_chunk_count = chunk_count_for_bytes(proof_bytes.len(), chunk_size_bytes)?;
    if chunk_count != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "proof chunk manifest chunk count does not match proof length",
        ));
    }
    let chunk_hashes = required_string_array_field(manifest, "chunkHashList")?;
    let proof_full_bytes_hash = required_string_field(manifest, "proofFullBytesHash")?;
    let chunk_merkle_root = required_string_field(manifest, "chunkMerkleRoot")?;
    let statement_hash = required_string_field(manifest, "statementHash")?;
    validate_direct_ballot_hash_hex(statement_hash, "proofChunkManifest.statementHash")?;
    let proof_profile_hash = required_string_field(manifest, "proofProfileHash")?;
    validate_direct_ballot_hash_hex(proof_profile_hash, "proofChunkManifest.proofProfileHash")?;
    let proof_header = direct_ballot_relation_proof_public_header(proof_bytes)?;
    if statement_hash != proof_header.statement_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "proof chunk manifest statementHash does not match proof bytes",
        ));
    }
    if proof_profile_hash != proof_header.proof_profile_hash {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "proof chunk manifest proofProfileHash does not match proof bytes",
        ));
    }
    validate_direct_ballot_hash_hex(
        required_string_field(manifest, "ciphertextRoot")?,
        "proofChunkManifest.ciphertextRoot",
    )?;
    validate_direct_ballot_hash_hex(
        required_string_field(manifest, "actionContextHash")?,
        "proofChunkManifest.actionContextHash",
    )?;
    validate_direct_ballot_hash_hex(
        required_string_field(manifest, "setupPackageRoot")?,
        "proofChunkManifest.setupPackageRoot",
    )?;
    verify_direct_ballot_public_proof_transport(
        proof_bytes,
        proof_full_bytes_hash,
        &chunk_hashes,
        chunk_size_bytes,
        chunk_merkle_root,
    )
}

pub(super) fn direct_ballot_encrypted_package(
    setup_package: &Value,
    ballot: &DirectEncryptedBallot,
    proof_statement: &DirectBallotValidityStatement,
    proof_manifest: &DirectBallotProofChunkManifest,
) -> CanonicalResult<DirectBallotEncryptedPackage> {
    let setup_context = direct_ballot_setup_context(setup_package)?;
    let profile_binding = direct_ballot_profile_binding(setup_package)?;
    let witness_partition_profile_hash = direct_ballot_witness_partition_profile_hash()?;
    let arithmetic_certificate_hash =
        required_string_field(&proof_statement.value, "arithmeticCertificateHash")?;
    let soundness_certificate_hash =
        required_string_field(&proof_statement.value, "soundnessCertificateHash")?;
    let zero_knowledge_certificate_hash =
        required_string_field(&proof_statement.value, "zeroKnowledgeCertificateHash")?;
    let verifier_certificate_hash =
        required_string_field(&proof_statement.value, "verifierCertificateHash")?;
    let unsigned_package = json!({
        "objectType": ENCRYPTED_BALLOT_PACKAGE_OBJECT_TYPE,
        "objectVersion": ENCRYPTED_BALLOT_PACKAGE_OBJECT_VERSION,
        "ceremonyId": setup_context.ceremony_id.as_str(),
        "manifestHash": setup_context.manifest_hash.as_str(),
        "rosterHash": setup_context.roster_hash.as_str(),
        "thresholdProfileHash": setup_context.threshold_profile_hash.as_str(),
        "setupPackageRoot": setup_context.setup_package_root.as_str(),
        "setupProfileHash": setup_context.setup_profile_hash.as_str(),
        "voterIdentity": ballot.input.voter_identity.as_str(),
        "voterRosterPosition": ballot.input.voter_roster_position,
        "actionContextHash": ballot.input.action_context_hash.as_str(),
        "recoveryEpoch": ballot.input.recovery_epoch,
        "deviceEpoch": ballot.input.device_epoch,
        "bgvProfileHash": profile_binding.bgv_profile_hash.as_str(),
        "batchEncoderHash": profile_binding.batch_encoder_hash.as_str(),
        "batchLayoutBindingHash": profile_binding.batch_layout_binding_hash.as_str(),
        "ballotScoreEncodingProfileHash": profile_binding.ballot_score_encoding_profile_hash.as_str(),
        "encryptedBallotLayoutHash": profile_binding.encrypted_ballot_layout_hash.as_str(),
        "directBallotReservedSlotRuleHash": profile_binding.direct_ballot_reserved_slot_rule_hash.as_str(),
        "directBallotEncoderMatrixRoot": profile_binding.direct_ballot_encoder_matrix_root.as_str(),
        "collectivePublicKeyRoot": setup_context.collective_public_key_root.as_str(),
        "bgvPublicKeyRoot": setup_context.bgv_public_key_root.as_str(),
        "ciphertextRoot": ballot.ciphertext_root.as_str(),
        "ciphertextTransport": direct_ballot_ciphertext_transport(&ballot.ciphertext, &ballot.ciphertext_root)?,
        "witnessPartitionProfileHash": witness_partition_profile_hash,
        "arithmeticCertificateHash": arithmetic_certificate_hash,
        "soundnessCertificateHash": soundness_certificate_hash,
        "zeroKnowledgeCertificateHash": zero_knowledge_certificate_hash,
        "verifierCertificateHash": verifier_certificate_hash,
        "proofProfileHash": required_string_field(&proof_statement.value, "proofProfileHash")?,
        "proofStatementHash": proof_statement.hash_hex.as_str(),
        "proofChunkManifest": proof_manifest.value.clone(),
        "proofFullBytesHash": required_string_field(&proof_manifest.value, "proofFullBytesHash")?,
        "proofChunkRoot": proof_manifest.root.as_str(),
    });
    let package_root = derive_protocol_hash("EncryptedBallotPackageRoot", &unsigned_package)?;
    let mut package = unsigned_package;
    package["packageRoot"] = json!(package_root.clone());
    package["signature"] = Value::Null;
    let voter_signature_signed_root =
        encrypted_ballot_package_voter_signature_signed_root(&package)?;

    Ok(DirectBallotEncryptedPackage {
        root: package["packageRoot"]
            .as_str()
            .expect("package root was inserted")
            .to_string(),
        value: package,
        voter_signature_signed_root,
    })
}

pub(super) fn encrypted_ballot_package_voter_signature_signed_root(
    package: &Value,
) -> CanonicalResult<Value> {
    let package_root = required_string_field(package, "packageRoot")?;
    validate_direct_ballot_hash_hex(package_root, "encryptedBallotPackage.packageRoot")?;
    let manifest_hash = required_string_field(package, "manifestHash")?;
    validate_direct_ballot_hash_hex(manifest_hash, "encryptedBallotPackage.manifestHash")?;
    let action_context_hash = required_string_field(package, "actionContextHash")?;
    validate_direct_ballot_hash_hex(
        action_context_hash,
        "encryptedBallotPackage.actionContextHash",
    )?;
    let signed_payload = encrypted_ballot_package_signed_payload(package)?;
    let byte_length = usize_to_u64(
        canonical_json(&signed_payload)?.as_bytes().len(),
        "encrypted ballot package signed payload byte length",
    )?;

    Ok(json!({
        "objectType": ENCRYPTED_BALLOT_PACKAGE_OBJECT_TYPE,
        "objectVersion": ENCRYPTED_BALLOT_PACKAGE_OBJECT_VERSION,
        "ceremonyId": required_string_field(package, "ceremonyId")?,
        "manifestHash": manifest_hash,
        "boardHeadHash": null,
        "objectRoot": package_root,
        "chunkMerkleRoot": null,
        "byteLength": byte_length,
        "signerRole": "Voter",
        "signerIdentity": required_string_field(package, "voterIdentity")?,
        "recoveryEpoch": required_u64_field(package, "recoveryEpoch")?,
        "deviceEpoch": required_u64_field(package, "deviceEpoch")?,
        "contextHash": action_context_hash,
    }))
}

pub(super) fn encrypted_ballot_package_signed_payload(package: &Value) -> CanonicalResult<Value> {
    let mut signed_payload = package
        .as_object()
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "encrypted ballot package must be an object",
            )
        })?
        .clone();
    signed_payload.remove("signature");

    Ok(Value::Object(signed_payload))
}

pub(super) struct DirectBallotSetupContext {
    pub(super) ceremony_id: String,
    pub(super) manifest_hash: String,
    pub(super) roster_hash: String,
    pub(super) threshold_profile_hash: String,
    pub(super) setup_package_root: String,
    pub(super) setup_profile_hash: String,
    pub(super) collective_public_key_root: String,
    pub(super) bgv_public_key_root: String,
}

pub(super) struct DirectBallotProfileBinding {
    pub(super) bgv_profile_hash: String,
    pub(super) batch_encoder_hash: String,
    pub(super) batch_layout_binding_hash: String,
    pub(super) ballot_score_encoding_profile_hash: String,
    pub(super) encrypted_ballot_layout_hash: String,
    pub(super) direct_ballot_reserved_slot_rule_hash: String,
    pub(super) direct_ballot_encoder_matrix_root: String,
    pub(super) verifier_certificate_hash: String,
}

struct DirectBallotValidityStatementBytesInput<'a> {
    setup_context: &'a DirectBallotSetupContext,
    profile_binding: &'a DirectBallotProfileBinding,
    ballot: &'a DirectEncryptedBallot,
    proof_profile_hash: &'a str,
    witness_partition_profile_hash: &'a str,
    arithmetic_certificate_hash: &'a str,
    soundness_certificate_hash: &'a str,
    zero_knowledge_certificate_hash: &'a str,
    verifier_certificate_hash: &'a str,
    ciphertext_limb_roots: &'a [Value],
    public_key_limb_roots: &'a [Value],
}

pub(super) fn direct_ballot_setup_context(
    setup_package: &Value,
) -> CanonicalResult<DirectBallotSetupContext> {
    if setup_package.get("objectType").and_then(Value::as_str)
        == Some(DIRECT_BALLOT_ACCEPTED_PUBLIC_KEY_MATERIAL_OBJECT_TYPE)
    {
        return direct_ballot_setup_context_from_accepted_public_key_material(setup_package);
    }

    let setup_package_root = setup_package_hash(setup_package)?;
    validate_direct_ballot_hash_hex(&setup_package_root, "setupPackageRoot")?;
    let setup_inputs = setup_package.get("setupInputs");
    let ceremony_id = string_from_optional_context(setup_package, setup_inputs, "ceremonyId")?;
    let manifest_hash = string_from_optional_context(setup_package, setup_inputs, "manifestHash")?;
    let roster_hash = string_from_optional_context(setup_package, setup_inputs, "rosterHash")?;
    let threshold_profile_hash =
        string_from_optional_context(setup_package, setup_inputs, "thresholdProfileHash")?;
    validate_direct_ballot_hash_hex(&manifest_hash, "manifestHash")?;
    validate_direct_ballot_hash_hex(&roster_hash, "rosterHash")?;
    validate_direct_ballot_hash_hex(&threshold_profile_hash, "thresholdProfileHash")?;
    let setup_profile_hash = match setup_package
        .get("setupContext")
        .and_then(|context| context.get("setupProfileHash"))
        .and_then(Value::as_str)
    {
        Some(hash) => hash.to_string(),
        None => profile_hash()?,
    };
    validate_direct_ballot_hash_hex(&setup_profile_hash, "setupProfileHash")?;
    let collective_public_key_root = required_string_path(
        setup_package,
        &["collectivePublicKey", "collectivePublicKeyRoot"],
    )?
    .to_string();
    let bgv_public_key_root =
        required_string_path(setup_package, &["collectivePublicKey", "bgvPublicKeyRoot"])?
            .to_string();
    validate_direct_ballot_hash_hex(&collective_public_key_root, "collectivePublicKeyRoot")?;
    validate_direct_ballot_hash_hex(&bgv_public_key_root, "bgvPublicKeyRoot")?;

    Ok(DirectBallotSetupContext {
        ceremony_id,
        manifest_hash,
        roster_hash,
        threshold_profile_hash,
        setup_package_root,
        setup_profile_hash,
        collective_public_key_root,
        bgv_public_key_root,
    })
}

fn direct_ballot_setup_context_from_accepted_public_key_material(
    accepted_public_key_material: &Value,
) -> CanonicalResult<DirectBallotSetupContext> {
    let setup_package_root =
        required_string_field(accepted_public_key_material, "setupPackageHash")?.to_string();
    validate_direct_ballot_hash_hex(&setup_package_root, "setupPackageRoot")?;
    let ceremony_id =
        required_string_field(accepted_public_key_material, "ceremonyId")?.to_string();
    let manifest_hash =
        required_string_field(accepted_public_key_material, "manifestHash")?.to_string();
    let roster_hash =
        required_string_field(accepted_public_key_material, "rosterHash")?.to_string();
    let threshold_profile_hash =
        required_string_field(accepted_public_key_material, "thresholdProfileHash")?.to_string();
    let setup_profile_hash =
        required_string_field(accepted_public_key_material, "setupProfileHash")?.to_string();
    let collective_public_key_root =
        required_string_field(accepted_public_key_material, "collectivePublicKeyRoot")?.to_string();
    let bgv_public_key_root =
        required_string_field(accepted_public_key_material, "bgvPublicKeyRoot")?.to_string();
    for (label, hash) in [
        ("manifestHash", manifest_hash.as_str()),
        ("rosterHash", roster_hash.as_str()),
        ("thresholdProfileHash", threshold_profile_hash.as_str()),
        ("setupProfileHash", setup_profile_hash.as_str()),
        (
            "collectivePublicKeyRoot",
            collective_public_key_root.as_str(),
        ),
        ("bgvPublicKeyRoot", bgv_public_key_root.as_str()),
    ] {
        validate_direct_ballot_hash_hex(hash, label)?;
    }

    Ok(DirectBallotSetupContext {
        ceremony_id,
        manifest_hash,
        roster_hash,
        threshold_profile_hash,
        setup_package_root,
        setup_profile_hash,
        collective_public_key_root,
        bgv_public_key_root,
    })
}

pub(super) fn direct_ballot_profile_binding(
    setup_package: &Value,
) -> CanonicalResult<DirectBallotProfileBinding> {
    if setup_package.get("objectType").and_then(Value::as_str)
        == Some(DIRECT_BALLOT_ACCEPTED_PUBLIC_KEY_MATERIAL_OBJECT_TYPE)
    {
        return direct_ballot_profile_binding_from_accepted_public_key_material(setup_package);
    }

    let package_bgv_profile_hash =
        required_string_path(setup_package, &["profileBindings", "profileHash"])?.to_string();
    let package_batch_encoder_hash =
        required_string_path(setup_package, &["profileBindings", "batchEncoderHash"])?.to_string();
    let package_batch_layout_binding_hash = required_string_path(
        setup_package,
        &["profileBindings", "batchLayoutBindingHash"],
    )?
    .to_string();
    let package_ballot_score_encoding_profile_hash = required_string_path(
        setup_package,
        &["profileBindings", "ballotScoreEncodingProfileHash"],
    )?
    .to_string();
    let package_encrypted_ballot_layout_hash = required_string_path(
        setup_package,
        &["profileBindings", "encryptedBallotLayoutHash"],
    )?
    .to_string();
    let package_direct_ballot_reserved_slot_rule_hash = required_string_path(
        setup_package,
        &["profileBindings", "directBallotReservedSlotRuleHash"],
    )?
    .to_string();
    let package_direct_ballot_encoder_matrix_root = required_string_path(
        setup_package,
        &["profileBindings", "directBallotEncoderMatrixRoot"],
    )?
    .to_string();
    let package_soundness_certificate_hash = required_string_path(
        setup_package,
        &["profileBindings", "soundnessCertificateHash"],
    )?
    .to_string();
    let package_zero_knowledge_certificate_hash = required_string_path(
        setup_package,
        &["profileBindings", "zeroKnowledgeCertificateHash"],
    )?
    .to_string();
    let package_verifier_certificate_hash = required_string_path(
        setup_package,
        &["profileBindings", "verifierCertificateHash"],
    )?
    .to_string();
    for (label, hash) in [
        ("bgvProfileHash", package_bgv_profile_hash.as_str()),
        ("batchEncoderHash", package_batch_encoder_hash.as_str()),
        (
            "batchLayoutBindingHash",
            package_batch_layout_binding_hash.as_str(),
        ),
        (
            "ballotScoreEncodingProfileHash",
            package_ballot_score_encoding_profile_hash.as_str(),
        ),
        (
            "encryptedBallotLayoutHash",
            package_encrypted_ballot_layout_hash.as_str(),
        ),
        (
            "directBallotReservedSlotRuleHash",
            package_direct_ballot_reserved_slot_rule_hash.as_str(),
        ),
        (
            "directBallotEncoderMatrixRoot",
            package_direct_ballot_encoder_matrix_root.as_str(),
        ),
        (
            "soundnessCertificateHash",
            package_soundness_certificate_hash.as_str(),
        ),
        (
            "zeroKnowledgeCertificateHash",
            package_zero_knowledge_certificate_hash.as_str(),
        ),
        (
            "verifierCertificateHash",
            package_verifier_certificate_hash.as_str(),
        ),
    ] {
        validate_direct_ballot_hash_hex(hash, label)?;
    }
    if package_bgv_profile_hash != profile_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package BGV profile hash does not match the selected profile",
        ));
    }
    if package_batch_encoder_hash != batch_encoder_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package batch encoder hash does not match the selected profile",
        ));
    }
    if package_batch_layout_binding_hash != batch_layout_binding_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package batch layout binding hash does not match the selected profile",
        ));
    }
    if package_ballot_score_encoding_profile_hash != ballot_score_encoding_profile_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package score encoding profile hash does not match the selected profile",
        ));
    }
    if package_encrypted_ballot_layout_hash != encrypted_ballot_layout_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package layout hash does not match the selected profile",
        ));
    }
    if package_direct_ballot_reserved_slot_rule_hash != direct_ballot_reserved_slot_rule_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package reserved slot rule hash does not match the selected profile",
        ));
    }
    if package_direct_ballot_encoder_matrix_root != direct_ballot_encoder_matrix_root()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package encoder matrix root does not match the selected profile",
        ));
    }
    if package_soundness_certificate_hash != direct_ballot_soundness_certificate_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package soundness certificate hash does not match the selected profile",
        ));
    }
    if package_zero_knowledge_certificate_hash != direct_ballot_zero_knowledge_certificate_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package zero-knowledge certificate hash does not match the selected profile",
        ));
    }
    if package_verifier_certificate_hash != direct_ballot_verifier_certificate_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "direct ballot package verifier certificate hash does not match the selected profile",
        ));
    }

    Ok(DirectBallotProfileBinding {
        bgv_profile_hash: package_bgv_profile_hash,
        batch_encoder_hash: package_batch_encoder_hash,
        batch_layout_binding_hash: package_batch_layout_binding_hash,
        ballot_score_encoding_profile_hash: package_ballot_score_encoding_profile_hash,
        encrypted_ballot_layout_hash: package_encrypted_ballot_layout_hash,
        direct_ballot_reserved_slot_rule_hash: package_direct_ballot_reserved_slot_rule_hash,
        direct_ballot_encoder_matrix_root: package_direct_ballot_encoder_matrix_root,
        verifier_certificate_hash: package_verifier_certificate_hash,
    })
}

fn direct_ballot_profile_binding_from_accepted_public_key_material(
    accepted_public_key_material: &Value,
) -> CanonicalResult<DirectBallotProfileBinding> {
    let package_bgv_profile_hash =
        required_string_field(accepted_public_key_material, "bgvProfileHash")?.to_string();
    let package_batch_encoder_hash =
        required_string_field(accepted_public_key_material, "batchEncoderHash")?.to_string();
    let package_batch_layout_binding_hash =
        required_string_field(accepted_public_key_material, "batchLayoutBindingHash")?.to_string();
    let package_ballot_score_encoding_profile_hash = required_string_field(
        accepted_public_key_material,
        "ballotScoreEncodingProfileHash",
    )?
    .to_string();
    let package_encrypted_ballot_layout_hash =
        required_string_field(accepted_public_key_material, "encryptedBallotLayoutHash")?
            .to_string();
    let package_direct_ballot_reserved_slot_rule_hash = required_string_field(
        accepted_public_key_material,
        "directBallotReservedSlotRuleHash",
    )?
    .to_string();
    let package_direct_ballot_encoder_matrix_root = required_string_field(
        accepted_public_key_material,
        "directBallotEncoderMatrixRoot",
    )?
    .to_string();
    let package_ballot_validity_proof_profile_hash = required_string_field(
        accepted_public_key_material,
        "ballotValidityProofProfileHash",
    )?
    .to_string();
    let package_soundness_certificate_hash =
        required_string_field(accepted_public_key_material, "soundnessCertificateHash")?
            .to_string();
    let package_zero_knowledge_certificate_hash =
        required_string_field(accepted_public_key_material, "zeroKnowledgeCertificateHash")?
            .to_string();
    let package_verifier_certificate_hash =
        required_string_field(accepted_public_key_material, "verifierCertificateHash")?.to_string();
    for (label, hash) in [
        ("bgvProfileHash", package_bgv_profile_hash.as_str()),
        ("batchEncoderHash", package_batch_encoder_hash.as_str()),
        (
            "batchLayoutBindingHash",
            package_batch_layout_binding_hash.as_str(),
        ),
        (
            "ballotScoreEncodingProfileHash",
            package_ballot_score_encoding_profile_hash.as_str(),
        ),
        (
            "encryptedBallotLayoutHash",
            package_encrypted_ballot_layout_hash.as_str(),
        ),
        (
            "directBallotReservedSlotRuleHash",
            package_direct_ballot_reserved_slot_rule_hash.as_str(),
        ),
        (
            "directBallotEncoderMatrixRoot",
            package_direct_ballot_encoder_matrix_root.as_str(),
        ),
        (
            "ballotValidityProofProfileHash",
            package_ballot_validity_proof_profile_hash.as_str(),
        ),
        (
            "soundnessCertificateHash",
            package_soundness_certificate_hash.as_str(),
        ),
        (
            "zeroKnowledgeCertificateHash",
            package_zero_knowledge_certificate_hash.as_str(),
        ),
        (
            "verifierCertificateHash",
            package_verifier_certificate_hash.as_str(),
        ),
    ] {
        validate_direct_ballot_hash_hex(hash, label)?;
    }
    if package_bgv_profile_hash != profile_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material BGV profile hash does not match the selected profile",
        ));
    }
    if package_batch_encoder_hash != batch_encoder_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material batch encoder hash does not match the selected profile",
        ));
    }
    if package_batch_layout_binding_hash != batch_layout_binding_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material batch layout binding hash does not match the selected profile",
        ));
    }
    if package_ballot_score_encoding_profile_hash != ballot_score_encoding_profile_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material score encoding profile hash does not match the selected profile",
        ));
    }
    if package_encrypted_ballot_layout_hash != encrypted_ballot_layout_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material layout hash does not match the selected profile",
        ));
    }
    if package_direct_ballot_reserved_slot_rule_hash != direct_ballot_reserved_slot_rule_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material reserved slot rule hash does not match the selected profile",
        ));
    }
    if package_direct_ballot_encoder_matrix_root != direct_ballot_encoder_matrix_root()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material encoder matrix root does not match the selected profile",
        ));
    }
    if package_ballot_validity_proof_profile_hash != direct_ballot_relation_proof_profile_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material ballot validity proof profile hash does not match the selected profile",
        ));
    }
    if package_soundness_certificate_hash != direct_ballot_soundness_certificate_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material soundness certificate hash does not match the selected profile",
        ));
    }
    if package_zero_knowledge_certificate_hash != direct_ballot_zero_knowledge_certificate_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material zero-knowledge certificate hash does not match the selected profile",
        ));
    }
    if package_verifier_certificate_hash != direct_ballot_verifier_certificate_hash()? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "accepted public key material verifier certificate hash does not match the selected profile",
        ));
    }

    Ok(DirectBallotProfileBinding {
        bgv_profile_hash: package_bgv_profile_hash,
        batch_encoder_hash: package_batch_encoder_hash,
        batch_layout_binding_hash: package_batch_layout_binding_hash,
        ballot_score_encoding_profile_hash: package_ballot_score_encoding_profile_hash,
        encrypted_ballot_layout_hash: package_encrypted_ballot_layout_hash,
        direct_ballot_reserved_slot_rule_hash: package_direct_ballot_reserved_slot_rule_hash,
        direct_ballot_encoder_matrix_root: package_direct_ballot_encoder_matrix_root,
        verifier_certificate_hash: package_verifier_certificate_hash,
    })
}

fn string_from_optional_context(
    setup_package: &Value,
    setup_inputs: Option<&Value>,
    field_name: &str,
) -> CanonicalResult<String> {
    setup_package
        .get("setupContext")
        .and_then(|context| context.get(field_name))
        .or_else(|| setup_inputs.and_then(|inputs| inputs.get(field_name)))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("setup package must bind {field_name}"),
            )
        })
}

fn direct_ballot_validity_statement_bytes(
    statement_inputs: DirectBallotValidityStatementBytesInput<'_>,
) -> CanonicalResult<Vec<u8>> {
    let DirectBallotValidityStatementBytesInput {
        setup_context,
        profile_binding,
        ballot,
        proof_profile_hash,
        witness_partition_profile_hash,
        arithmetic_certificate_hash,
        soundness_certificate_hash,
        zero_knowledge_certificate_hash,
        verifier_certificate_hash,
        ciphertext_limb_roots,
        public_key_limb_roots,
    } = statement_inputs;
    let mut bytes = Vec::new();
    append_string(&mut bytes, DIRECT_BALLOT_STATEMENT_BINARY_MAGIC);
    append_string(&mut bytes, BALLOT_VALIDITY_STATEMENT_ID);
    append_varuint(&mut bytes, 1);
    append_hash_string(&mut bytes, &setup_context.manifest_hash, "manifestHash")?;
    append_hash_string(&mut bytes, &setup_context.roster_hash, "rosterHash")?;
    append_hash_string(
        &mut bytes,
        &setup_context.threshold_profile_hash,
        "thresholdProfileHash",
    )?;
    append_hash_string(
        &mut bytes,
        &setup_context.setup_package_root,
        "setupPackageRoot",
    )?;
    append_hash_string(
        &mut bytes,
        &setup_context.setup_profile_hash,
        "setupProfileHash",
    )?;
    append_string(&mut bytes, &setup_context.ceremony_id);
    append_string(&mut bytes, &ballot.input.voter_identity);
    append_varuint(
        &mut bytes,
        usize_to_u64(ballot.input.voter_roster_position, "voter roster position")?,
    );
    append_hash_string(
        &mut bytes,
        &ballot.input.action_context_hash,
        "actionContextHash",
    )?;
    append_hash_string(
        &mut bytes,
        &setup_context.collective_public_key_root,
        "collectivePublicKeyRoot",
    )?;
    append_hash_string(
        &mut bytes,
        &setup_context.bgv_public_key_root,
        "bgvPublicKeyRoot",
    )?;
    append_hash_string(
        &mut bytes,
        &profile_binding.bgv_profile_hash,
        "bgvProfileHash",
    )?;
    append_hash_string(
        &mut bytes,
        &profile_binding.batch_encoder_hash,
        "batchEncoderHash",
    )?;
    append_hash_string(
        &mut bytes,
        &profile_binding.batch_layout_binding_hash,
        "batchLayoutBindingHash",
    )?;
    append_hash_string(
        &mut bytes,
        &profile_binding.ballot_score_encoding_profile_hash,
        "ballotScoreEncodingProfileHash",
    )?;
    append_hash_string(
        &mut bytes,
        &profile_binding.encrypted_ballot_layout_hash,
        "encryptedBallotLayoutHash",
    )?;
    append_hash_string(
        &mut bytes,
        &profile_binding.direct_ballot_reserved_slot_rule_hash,
        "directBallotReservedSlotRuleHash",
    )?;
    append_hash_string(
        &mut bytes,
        &profile_binding.direct_ballot_encoder_matrix_root,
        "directBallotEncoderMatrixRoot",
    )?;
    append_hash_string(&mut bytes, &ballot.ciphertext_root, "ciphertextRoot")?;
    append_hash_string(
        &mut bytes,
        witness_partition_profile_hash,
        "witnessPartitionProfileHash",
    )?;
    append_hash_string(
        &mut bytes,
        arithmetic_certificate_hash,
        "arithmeticCertificateHash",
    )?;
    append_hash_string(
        &mut bytes,
        soundness_certificate_hash,
        "soundnessCertificateHash",
    )?;
    append_hash_string(
        &mut bytes,
        zero_knowledge_certificate_hash,
        "zeroKnowledgeCertificateHash",
    )?;
    append_hash_string(
        &mut bytes,
        verifier_certificate_hash,
        "verifierCertificateHash",
    )?;
    append_hash_string(&mut bytes, proof_profile_hash, "proofProfileHash")?;
    append_root_records(&mut bytes, ciphertext_limb_roots, "ciphertextLimbRoots")?;
    append_root_records(&mut bytes, public_key_limb_roots, "publicKeyLimbRoots")?;

    Ok(bytes)
}

fn append_root_records(
    output: &mut Vec<u8>,
    records: &[Value],
    label: &str,
) -> CanonicalResult<()> {
    append_varuint(output, usize_to_u64(records.len(), label)?);
    for (record_index, record) in records.iter().enumerate() {
        append_varuint(
            output,
            required_u64_field(record, "componentIndex").or_else(
                |_| match required_string_field(record, "component")? {
                    "componentZero" => Ok(0),
                    "componentOne" => Ok(1),
                    _ => Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{label}[{record_index}].component is not recognized"),
                    )),
                },
            )?,
        );
        append_varuint(output, required_u64_field(record, "limbIndex")?);
        append_varuint(output, required_u64_field(record, "modulus")?);
        append_hash_string(
            output,
            required_string_field(record, "limbRoot")?,
            &format!("{label}[{record_index}].limbRoot"),
        )?;
    }
    Ok(())
}

fn append_hash_string(output: &mut Vec<u8>, value: &str, label: &str) -> CanonicalResult<()> {
    validate_direct_ballot_hash_hex(value, label)?;
    append_string(output, value);
    Ok(())
}

pub(super) fn reject_unexpected_direct_ballot_object_fields(
    value: &Value,
    object_path: &str,
    allowed_fields: &[&str],
) -> CanonicalResult<()> {
    let object = value.as_object().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_path} must be an object"),
        )
    })?;
    if let Some(field_name) = object
        .keys()
        .find(|field_name| !allowed_fields.contains(&field_name.as_str()))
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{object_path} contains unexpected field {field_name}"),
        ));
    }

    Ok(())
}

pub(super) fn direct_ballot_ciphertext_limb_roots(
    ballot: &DirectEncryptedBallot,
) -> CanonicalResult<Vec<Value>> {
    direct_ballot_ciphertext_limb_roots_from_ciphertext(&ballot.ciphertext)
}

pub(super) fn direct_ballot_ciphertext_transport(
    ciphertext: &Ciphertext,
    expected_ciphertext_root: &str,
) -> CanonicalResult<Value> {
    validate_direct_ballot_hash_hex(expected_ciphertext_root, "ciphertextRoot")?;
    let ciphertext_root = ciphertext_object_root(ciphertext)?;
    if ciphertext_root != expected_ciphertext_root {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "ciphertext transport root does not match the supplied ciphertext",
        ));
    }
    let canonical_bytes_hex = ciphertext_canonical_bytes_hex(ciphertext)?;

    Ok(json!({
        "encoding": "sealed-lattice-bgv-rns-canonical-ciphertext-v1",
        "canonicalByteLength": canonical_bytes_hex.len() / 2,
        "canonicalBytesHex": canonical_bytes_hex,
        "ciphertextRoot": expected_ciphertext_root,
        "ciphertextLimbRoots": direct_ballot_ciphertext_limb_roots_from_ciphertext(ciphertext)?,
    }))
}

pub(super) fn direct_ballot_ciphertext_limb_roots_from_ciphertext(
    ciphertext: &Ciphertext,
) -> CanonicalResult<Vec<Value>> {
    if ciphertext.components.len() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct ballot package ciphertext must have two components",
        ));
    }
    let mut limb_roots = Vec::with_capacity(2 * DATA_PRIMES.len());
    for (component_index, component) in ciphertext.components.iter().enumerate() {
        if component.len() != DATA_PRIMES.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct ballot package ciphertext component does not match the data basis",
            ));
        }
        for (limb_index, (limb, modulus)) in component.iter().zip(DATA_PRIMES.iter()).enumerate() {
            let limb_root = direct_ballot_limb_root(
                DIRECT_BALLOT_CIPHERTEXT_LIMB_ROOT_DOMAIN,
                component_index,
                limb_index,
                *modulus,
                limb,
                "ciphertext",
            )?;
            limb_roots.push(json!({
                "componentIndex": component_index,
                "limbIndex": limb_index,
                "modulus": modulus,
                "limbRoot": limb_root,
            }));
        }
    }

    Ok(limb_roots)
}

fn direct_ballot_public_key_limb_roots(public_key: &BgvPublicKey) -> CanonicalResult<Vec<Value>> {
    let (public_component_zero, public_component_one) = public_key.public_key_components();
    let public_key_components = [
        ("componentZero", public_component_zero),
        ("componentOne", public_component_one),
    ];
    let mut limb_roots = Vec::with_capacity(2 * DATA_PRIMES.len());
    for (component_index, (component_name, component)) in public_key_components.iter().enumerate() {
        if component.len() != DATA_PRIMES.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "direct ballot package public key component does not match the data basis",
            ));
        }
        for (limb_index, (limb, modulus)) in component.iter().zip(DATA_PRIMES.iter()).enumerate() {
            let limb_root = direct_ballot_limb_root(
                DIRECT_BALLOT_PUBLIC_KEY_LIMB_ROOT_DOMAIN,
                component_index,
                limb_index,
                *modulus,
                limb,
                "public key",
            )?;
            limb_roots.push(json!({
                "component": component_name,
                "limbIndex": limb_index,
                "modulus": modulus,
                "limbRoot": limb_root,
            }));
        }
    }

    Ok(limb_roots)
}

fn direct_ballot_limb_root(
    domain: &str,
    component_index: usize,
    limb_index: usize,
    modulus: u64,
    coefficients: &[u64],
    label: &str,
) -> CanonicalResult<String> {
    if coefficients.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{label} limb does not match the polynomial degree"),
        ));
    }
    let mut bytes = Vec::with_capacity(24 + coefficients.len() * 8);
    append_varuint(
        &mut bytes,
        usize_to_u64(component_index, "component index")?,
    );
    append_varuint(&mut bytes, usize_to_u64(limb_index, "limb index")?);
    append_varuint(&mut bytes, modulus);
    append_varuint(
        &mut bytes,
        usize_to_u64(coefficients.len(), "coefficient count")?,
    );
    for coefficient in coefficients {
        if *coefficient >= modulus {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{label} limb has a non-canonical coefficient"),
            ));
        }
        bytes.extend_from_slice(&coefficient.to_le_bytes());
    }

    Ok(hash512_hex(domain, &[bytes.as_slice()]))
}
