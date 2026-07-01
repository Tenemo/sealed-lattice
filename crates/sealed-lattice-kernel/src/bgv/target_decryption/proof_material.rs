use super::*;

const TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareProofMaterial";
const TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareProofRecord";
#[cfg(feature = "target-decryption-development-commands")]
const TARGET_DECRYPTION_SHARE_BINARY_PROOF_MATERIAL_TRANSPORT_OBJECT_TYPE: &str =
    "BgvTargetDecryptionShareBinaryProofMaterialTransport";
#[cfg(feature = "target-decryption-development-commands")]
const TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_BINARY_FORMAT: &str =
    "sealed-lattice-target-decryption-share-proof-material-binary-v1";
#[cfg(feature = "target-decryption-development-commands")]
const TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_BINARY_MAGIC: &[u8] =
    b"SEALED-LATTICE-TARGET-DECRYPTION-SHARE-PROOF-MATERIAL-BINARY-V1";
const TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_VERSION: u64 = 8;
const TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_VERSION: u64 = 7;

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) struct TargetDecryptionShareProofMaterialGenerationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) local_target_share_witness: &'a Value,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) proof_randomness_seed_hex: &'a str,
    pub(super) proof_randomness_nonce_hex: &'a str,
}

pub(super) struct TargetDecryptionShareProofMaterialVerificationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) proof_material: &'a Value,
}

#[cfg(feature = "target-decryption-development-commands")]
pub(super) struct TargetDecryptionShareBinaryProofMaterialVerificationInput<'a> {
    pub(super) setup_binding: &'a SetupBinding,
    pub(super) target_accepted: &'a TargetAcceptedBinding,
    pub(super) target_ciphertexts: &'a TargetCiphertextPair,
    pub(super) target_share_profile: &'a TargetShareProfile,
    pub(super) participant: &'a ParticipantBinding,
    pub(super) target_decryption_share: &'a Value,
    pub(super) proof_statement: &'a Value,
    pub(super) transported_proof_material: &'a Value,
}

struct TargetDecryptionShareProofRecordVerificationInput<'a> {
    proof_record: &'a Value,
    setup_binding: &'a SetupBinding,
    target_accepted: &'a TargetAcceptedBinding,
    target_ciphertexts: &'a TargetCiphertextPair,
    participant: &'a ParticipantBinding,
    target_decryption_share: &'a Value,
    target_share_proof_statement: &'a Value,
    active_limb_count: usize,
}

#[cfg(feature = "target-decryption-development-commands")]
struct TargetDecryptionShareBinaryProofMaterialDecode {
    proof_material: Value,
    proof_record_count: usize,
    total_proof_byte_length: u64,
}

#[cfg(any(feature = "target-decryption-development-commands", test))]
pub(super) fn generate_target_decryption_share_proof_material_from_local_witness(
    input: TargetDecryptionShareProofMaterialGenerationInput<'_>,
) -> CanonicalResult<Value> {
    validate_target_decryption_share_proof_statement_shape(
        input.proof_statement,
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
        input.target_share_profile,
        input.participant,
        input.target_decryption_share,
    )?;
    let proof_slice_request =
        target_decryption_share_all_active_limbs_proof_request_from_local_witness(
            TargetDecryptionShareAllActiveLimbsProofRequestInput {
                setup_binding: input.setup_binding,
                target_accepted: input.target_accepted,
                target_ciphertexts: input.target_ciphertexts,
                target_share_profile: input.target_share_profile,
                participant: input.participant,
                local_target_share_witness: input.local_target_share_witness,
                target_decryption_share: input.target_decryption_share,
                proof_statement: input.proof_statement,
                proof_randomness_seed_hex: input.proof_randomness_seed_hex,
                proof_randomness_nonce_hex: input.proof_randomness_nonce_hex,
            },
        )?;
    let generated = crate::bgv::setup::generate_target_decryption_share_proof_bytes_from_request(
        &proof_slice_request,
    )?;
    let expected_target_roles = expected_target_roles();
    if generated.target_roles != expected_target_roles {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target-decryption proof material generator returned noncanonical target-role coverage",
        ));
    }
    let active_limb_count = input.target_ciphertexts.target_id.level + 1;
    let expected_target_rns_limb_indices = (0..active_limb_count).collect::<Vec<_>>();
    if generated.target_rns_limb_indices != expected_target_rns_limb_indices {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "target-decryption proof material generator returned noncanonical active-limb coverage",
        ));
    }
    let proof_bytes = generated.proof_bytes;
    let proof_bytes_base64 = encode_standard_base64(&proof_bytes);
    let proof_record = json!({
        "objectType": TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE,
        "objectVersion": TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_VERSION,
        "proofBytesBase64": proof_bytes_base64,
    });

    let mut proof_material = json!({
        "objectType": TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE,
        "objectVersion": TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_VERSION,
        "proofRecords": [proof_record],
    });
    proof_material["proofMaterialRoot"] = json!(derive_protocol_hash(
        "TargetDecryptionShareProofMaterialRoot",
        &target_decryption_share_proof_material_root_preimage(&proof_material)?
    )?);

    Ok(proof_material)
}

pub(super) fn verify_target_decryption_share_proof_material(
    input: TargetDecryptionShareProofMaterialVerificationInput<'_>,
) -> CanonicalResult<Value> {
    validate_target_decryption_share_proof_statement_shape(
        input.proof_statement,
        input.setup_binding,
        input.target_accepted,
        input.target_ciphertexts,
        input.target_share_profile,
        input.participant,
        input.target_decryption_share,
    )?;
    if string_at_path(input.proof_material, &["objectType"])?
        != TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE
        || unsigned_at_path(input.proof_material, &["objectVersion"])?
            != TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_VERSION
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proof material must use the current compact target proof-material layout",
        ));
    }
    hash_at_path(input.proof_material, &["proofMaterialRoot"])?;
    let expected_material_root = derive_protocol_hash(
        "TargetDecryptionShareProofMaterialRoot",
        &target_decryption_share_proof_material_root_preimage(input.proof_material)?,
    )?;
    compare_hash_field(
        input.proof_material,
        "proofMaterialRoot",
        &expected_material_root,
        "target-decryption proof material root",
    )?;

    let active_limb_count = input.target_ciphertexts.target_id.level + 1;
    let proof_records = array_at_path(input.proof_material, &["proofRecords"])?;
    if proof_records.len() != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption proof material must include one all-active-limb proof record",
        ));
    }

    for proof_record in proof_records {
        verify_target_decryption_share_proof_record(
            TargetDecryptionShareProofRecordVerificationInput {
                proof_record,
                setup_binding: input.setup_binding,
                target_accepted: input.target_accepted,
                target_ciphertexts: input.target_ciphertexts,
                participant: input.participant,
                target_decryption_share: input.target_decryption_share,
                target_share_proof_statement: input.proof_statement,
                active_limb_count,
            },
        )?;
    }

    Ok(json!({
        "ok": true,
        "operation": "verifyBgvTargetDecryptionShareProofMaterial",
        "proofMaterialRoot": expected_material_root,
    }))
}

#[cfg(feature = "target-decryption-development-commands")]
pub(super) fn verify_target_decryption_share_binary_proof_material(
    input: TargetDecryptionShareBinaryProofMaterialVerificationInput<'_>,
) -> CanonicalResult<Value> {
    let decoded = target_decryption_share_proof_material_from_binary_transport(
        input.transported_proof_material,
    )?;
    let verification = verify_target_decryption_share_proof_material(
        TargetDecryptionShareProofMaterialVerificationInput {
            setup_binding: input.setup_binding,
            target_accepted: input.target_accepted,
            target_ciphertexts: input.target_ciphertexts,
            target_share_profile: input.target_share_profile,
            participant: input.participant,
            target_decryption_share: input.target_decryption_share,
            proof_statement: input.proof_statement,
            proof_material: &decoded.proof_material,
        },
    )?;

    Ok(json!({
        "ok": true,
        "operation": "verifyBgvTargetDecryptionShareBinaryProofMaterial",
        "proofFamily": TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        "proofMaterialRoot": verification["proofMaterialRoot"].clone(),
        "proofRecordCount": decoded.proof_record_count,
        "totalProofByteLength": decoded.total_proof_byte_length,
        "binaryFormat": TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_BINARY_FORMAT,
        "binaryTotalByteLength": unsigned_at_path(input.transported_proof_material, &["totalByteLength"])?,
        "binaryChunkCount": unsigned_at_path(input.transported_proof_material, &["chunkCount"])?,
        "binaryFullObjectHash": hash_at_path(input.transported_proof_material, &["fullObjectHash"])?,
        "binaryChunkRoot": hash_at_path(input.transported_proof_material, &["chunkRoot"])?,
    }))
}

#[cfg(feature = "target-decryption-development-commands")]
fn target_decryption_share_proof_material_from_binary_transport(
    transported_proof_material: &Value,
) -> CanonicalResult<TargetDecryptionShareBinaryProofMaterialDecode> {
    target_decryption_verify_binary_transport_header(transported_proof_material)?;
    let chunks = target_decryption_binary_transport_chunks(transported_proof_material)?;
    target_decryption_verify_binary_transport_hashes(transported_proof_material, &chunks)?;
    let bytes = target_decryption_concatenate_binary_transport_chunks(&chunks)?;
    let mut reader = crate::encoding::CanonicalReader::new(&bytes);
    let magic = reader.read_exact(TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_BINARY_MAGIC.len())?;
    if magic != TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_BINARY_MAGIC {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedMagic,
            "target-decryption share proof material binary magic is invalid",
        ));
    }
    if reader.read_varuint()? != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::UnsupportedObjectVersion,
            "target-decryption share proof material binary version is not supported",
        ));
    }

    let proof_material_root = target_decryption_read_binary_hash(&mut reader, "proofMaterialRoot")?;
    compare_target_decryption_binary_string(
        &proof_material_root,
        hash_at_path(transported_proof_material, &["proofMaterialRoot"])?,
        "target-decryption share proof material binary proofMaterialRoot",
    )?;

    let proof_record_count = target_decryption_read_binary_usize(&mut reader, "proofRecordCount")?;
    if proof_record_count != 1 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption share proof material binary must contain one all-active-limb proof record",
        ));
    }

    let mut total_proof_byte_length = 0_u64;
    let mut proof_records = Vec::with_capacity(proof_record_count);
    for _proof_record_index in 0..proof_record_count {
        let proof_byte_length =
            target_decryption_read_binary_usize(&mut reader, "proofByteLength")?;
        let proof_bytes = reader.read_exact(proof_byte_length)?.to_vec();
        total_proof_byte_length = total_proof_byte_length
            .checked_add(u64::try_from(proof_bytes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption share proof material proof byte length does not fit u64",
                )
            })?)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption share proof material proof byte length overflowed",
                )
            })?;
        proof_records.push(json!({
            "objectType": TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE,
            "objectVersion": TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_VERSION,
            "proofBytesBase64": encode_standard_base64(&proof_bytes),
        }));
    }

    if !reader.is_finished() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::TrailingBytes,
            "target-decryption share proof material binary has trailing bytes",
        ));
    }

    Ok(TargetDecryptionShareBinaryProofMaterialDecode {
        proof_material: json!({
            "objectType": TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_TYPE,
            "objectVersion": TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_OBJECT_VERSION,
            "proofRecords": proof_records,
            "proofMaterialRoot": proof_material_root,
        }),
        proof_record_count,
        total_proof_byte_length,
    })
}

#[cfg(feature = "target-decryption-development-commands")]
fn target_decryption_verify_binary_transport_header(
    transported_proof_material: &Value,
) -> CanonicalResult<()> {
    compare_target_decryption_binary_string(
        string_at_path(transported_proof_material, &["objectType"])?,
        TARGET_DECRYPTION_SHARE_BINARY_PROOF_MATERIAL_TRANSPORT_OBJECT_TYPE,
        "target-decryption share proof material binary transport objectType",
    )?;
    compare_unsigned_field(
        transported_proof_material,
        "objectVersion",
        1,
        "target-decryption share proof material binary transport objectVersion",
    )?;
    compare_target_decryption_binary_string(
        string_at_path(transported_proof_material, &["setupProfileId"])?,
        COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "target-decryption share proof material binary transport setupProfileId",
    )?;
    compare_target_decryption_binary_string(
        string_at_path(transported_proof_material, &["targetDecryptionProfileId"])?,
        TARGET_DECRYPTION_PROFILE_ID,
        "target-decryption share proof material binary transport targetDecryptionProfileId",
    )?;
    compare_target_decryption_binary_string(
        string_at_path(transported_proof_material, &["proofFamily"])?,
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        "target-decryption share proof material binary transport proofFamily",
    )?;
    compare_target_decryption_binary_string(
        string_at_path(transported_proof_material, &["binaryFormat"])?,
        TARGET_DECRYPTION_SHARE_PROOF_MATERIAL_BINARY_FORMAT,
        "target-decryption share proof material binary transport binaryFormat",
    )?;
    hash_at_path(transported_proof_material, &["proofMaterialRoot"])?;
    hash_at_path(transported_proof_material, &["fullObjectHash"])?;
    hash_at_path(transported_proof_material, &["chunkRoot"])?;
    compare_unsigned_field(
        transported_proof_material,
        "chunkSizeBytes",
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        "target-decryption share proof material binary transport chunkSizeBytes",
    )?;

    Ok(())
}

#[cfg(feature = "target-decryption-development-commands")]
fn target_decryption_binary_transport_chunks(
    transported_proof_material: &Value,
) -> CanonicalResult<Vec<Vec<u8>>> {
    let chunk_values = array_at_path(transported_proof_material, &["chunks"])?;
    if chunk_values.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption share proof material binary transport chunks must be non-empty",
        ));
    }

    chunk_values
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk_value)| {
            let bytes_hex = string_at_path(chunk_value, &["bytesHex"])?;
            decode_hex(bytes_hex).map_err(|error| {
                CanonicalError::new(
                    error.code,
                    format!(
                        "target-decryption share proof material binary transport chunks[{chunk_index}].bytesHex: {}",
                        error.message
                    ),
                )
            })
        })
        .collect()
}

#[cfg(feature = "target-decryption-development-commands")]
fn target_decryption_verify_binary_transport_hashes(
    transported_proof_material: &Value,
    chunks: &[Vec<u8>],
) -> CanonicalResult<()> {
    let chunk_count = unsigned_at_path(transported_proof_material, &["chunkCount"])?;
    let observed_chunk_count = u64::try_from(chunks.len()).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption share proof material binary chunk count does not fit u64",
        )
    })?;
    if observed_chunk_count != chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption share proof material binary transport chunkCount does not match chunks length",
        ));
    }

    let total_byte_length = chunks.iter().enumerate().try_fold(
        0_u64,
        |byte_count, (chunk_index, chunk)| {
            if chunk.is_empty() {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption share proof material binary transport chunks must be non-empty",
                ));
            }
            if chunk.len() as u64 > SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption share proof material binary transport chunk exceeds chunkSizeBytes",
                ));
            }
            if chunk_index + 1 < chunks.len()
                && chunk.len() as u64 != SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES
            {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "target-decryption share proof material binary transport contains a short non-final chunk",
                ));
            }
            byte_count
                .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target-decryption share proof material binary chunk length does not fit u64",
                    )
                })?)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "target-decryption share proof material binary byte length overflowed",
                    )
                })
        },
    )?;
    if total_byte_length != unsigned_at_path(transported_proof_material, &["totalByteLength"])? {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption share proof material binary transport totalByteLength does not match chunks",
        ));
    }

    let expected_full_object_hash = setup_proof_material_full_object_hash(
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        total_byte_length,
        chunks,
    )?;
    compare_target_decryption_binary_string(
        hash_at_path(transported_proof_material, &["fullObjectHash"])?,
        &expected_full_object_hash,
        "target-decryption share proof material binary transport fullObjectHash",
    )?;
    let mut expected_chunk_hashes = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        expected_chunk_hashes.push(setup_proof_material_chunk_hash(
            TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
            &expected_full_object_hash,
            chunk_index,
            chunk,
        )?);
    }
    let chunk_hash_values = array_at_path(transported_proof_material, &["chunkHashes"])?;
    if chunk_hash_values.len() != expected_chunk_hashes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "target-decryption share proof material binary transport chunkHashes length must match chunks length",
        ));
    }
    for (chunk_index, expected_chunk_hash) in expected_chunk_hashes.iter().enumerate() {
        let observed_chunk_hash = chunk_hash_values
            .get(chunk_index)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "target-decryption share proof material binary transport chunkHashes entries must be strings",
                )
            })?;
        hash_at_path(&json!({ "chunkHash": observed_chunk_hash }), &["chunkHash"])?;
        compare_target_decryption_binary_string(
            observed_chunk_hash,
            expected_chunk_hash,
            &format!(
                "target-decryption share proof material binary transport chunkHashes[{chunk_index}]"
            ),
        )?;
    }
    let expected_chunk_root = setup_proof_material_chunk_manifest_root(
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        SETUP_PROOF_TRANSPORT_CHUNK_SIZE_BYTES,
        chunk_count,
        total_byte_length,
        &expected_chunk_hashes,
        &expected_full_object_hash,
    )?;
    compare_target_decryption_binary_string(
        hash_at_path(transported_proof_material, &["chunkRoot"])?,
        &expected_chunk_root,
        "target-decryption share proof material binary transport chunkRoot",
    )?;

    Ok(())
}

#[cfg(feature = "target-decryption-development-commands")]
fn target_decryption_concatenate_binary_transport_chunks(
    chunks: &[Vec<u8>],
) -> CanonicalResult<Vec<u8>> {
    let total_byte_length = chunks.iter().try_fold(0_usize, |byte_count, chunk| {
        byte_count.checked_add(chunk.len()).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "target-decryption share proof material binary byte length overflowed",
            )
        })
    })?;
    let mut bytes = Vec::with_capacity(total_byte_length);
    for chunk in chunks {
        bytes.extend_from_slice(chunk);
    }

    Ok(bytes)
}

#[cfg(feature = "target-decryption-development-commands")]
fn target_decryption_read_binary_hash(
    reader: &mut crate::encoding::CanonicalReader<'_>,
    _field_name: &str,
) -> CanonicalResult<String> {
    Ok(encode_hex(reader.read_exact(64)?))
}

#[cfg(feature = "target-decryption-development-commands")]
fn target_decryption_read_binary_usize(
    reader: &mut crate::encoding::CanonicalReader<'_>,
    field_name: &str,
) -> CanonicalResult<usize> {
    usize::try_from(reader.read_varuint()?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!(
                "target-decryption share proof material binary {field_name} does not fit usize"
            ),
        )
    })
}

#[cfg(feature = "target-decryption-development-commands")]
fn compare_target_decryption_binary_string(
    actual: &str,
    expected: &str,
    description: &str,
) -> CanonicalResult<()> {
    if actual != expected {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{description} does not match its target decryption binding"),
        ));
    }

    Ok(())
}

fn verify_target_decryption_share_proof_record(
    input: TargetDecryptionShareProofRecordVerificationInput<'_>,
) -> CanonicalResult<()> {
    let proof_record = input.proof_record;
    if string_at_path(proof_record, &["objectType"])?
        != TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_TYPE
        || unsigned_at_path(proof_record, &["objectVersion"])?
            != TARGET_DECRYPTION_SHARE_PROOF_RECORD_OBJECT_VERSION
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proof record must use the current compact target proof-record layout",
        ));
    }
    let expected_target_rns_limb_indices = (0..input.active_limb_count).collect::<Vec<_>>();
    let expected_target_roles = expected_target_roles();
    let proof_bytes = decode_standard_base64(
        string_at_path(proof_record, &["proofBytesBase64"])?,
        "target-decryption proofBytesBase64",
    )?;
    let proof_verification_request =
        target_decryption_share_all_active_limbs_proof_statement_from_public_inputs(
            TargetDecryptionShareAllActiveLimbsProofStatementInput {
                setup_binding: input.setup_binding,
                target_accepted: input.target_accepted,
                target_ciphertexts: input.target_ciphertexts,
                participant: input.participant,
                target_decryption_share: input.target_decryption_share,
                proof_statement: input.target_share_proof_statement,
            },
        )?;
    let proof_verification =
        crate::bgv::setup::verify_target_decryption_share_proof_bytes_from_request(
            &proof_verification_request,
            &proof_bytes,
        )?;
    compare_string_field(
        &proof_verification,
        "proofFamily",
        TARGET_DECRYPTION_SHARE_PROOF_FAMILY,
        "target-decryption proof verification proof family",
    )?;
    compare_hash_field(
        &proof_verification,
        "proofAccountingHash",
        &crate::bgv::setup::succinct_target_decryption_share_accounting_hash()?,
        "target-decryption proof verification accounting hash",
    )?;
    compare_target_roles_field(
        &proof_verification,
        &expected_target_roles,
        "target-decryption proof verification target roles",
    )?;
    compare_target_limb_indices_field(
        &proof_verification,
        &expected_target_rns_limb_indices,
        "target-decryption proof verification target limbs",
    )?;
    compare_unsigned_field(
        &proof_verification,
        "proofByteLength",
        proof_bytes.len() as u64,
        "target-decryption proof verification proof byte length",
    )?;

    Ok(())
}

fn expected_target_roles() -> Vec<String> {
    TARGET_DECRYPTION_SMUDGING_ROLES
        .iter()
        .map(|target_role| (*target_role).to_string())
        .collect()
}

fn compare_target_roles_field(
    value: &Value,
    expected_target_roles: &[String],
    field_description: &str,
) -> CanonicalResult<()> {
    let actual_target_roles = array_at_path(value, &["targetRoles"])?;
    if actual_target_roles.len() != expected_target_roles.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{field_description} count does not match"),
        ));
    }
    for (actual_role, expected_role) in actual_target_roles.iter().zip(expected_target_roles) {
        if actual_role.as_str() != Some(expected_role.as_str()) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("{field_description} do not match"),
            ));
        }
    }

    Ok(())
}

fn compare_target_limb_indices_field(
    value: &Value,
    expected_target_rns_limb_indices: &[usize],
    field_description: &str,
) -> CanonicalResult<()> {
    let actual_target_rns_limb_indices = array_at_path(value, &["targetRnsLimbIndices"])?;
    if actual_target_rns_limb_indices.len() != expected_target_rns_limb_indices.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            format!("{field_description} count does not match"),
        ));
    }
    for (actual_target_rns_limb_index, expected_target_rns_limb_index) in
        actual_target_rns_limb_indices
            .iter()
            .zip(expected_target_rns_limb_indices)
    {
        if actual_target_rns_limb_index.as_u64() != Some(*expected_target_rns_limb_index as u64) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ProfileComponentMismatch,
                format!("{field_description} do not match"),
            ));
        }
    }

    Ok(())
}

fn target_decryption_share_proof_material_root_preimage(
    proof_material: &Value,
) -> CanonicalResult<Value> {
    let mut root_preimage = proof_material.clone();
    let root_preimage_object = root_preimage.as_object_mut().ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target-decryption proof material root preimage must be an object",
        )
    })?;
    root_preimage_object.remove("proofMaterialRoot");
    Ok(root_preimage)
}
