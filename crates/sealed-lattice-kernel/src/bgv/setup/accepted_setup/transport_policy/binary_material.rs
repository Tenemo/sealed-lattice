use super::certificate::*;
use super::*;

pub(super) fn verify_binary_vss_material_transport_reference(
    setup_package: &Value,
    expected_byte_length: u64,
    expected_chunk_count: u64,
    expected_chunk_root: &str,
    expected_full_object_hash: &str,
) -> CanonicalResult<Result<(), Refusal>> {
    let material_set = setup_package
        .get("vssCoefficientCommitmentMaterial")
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "vssCoefficientCommitmentMaterial was required before setup transport verification",
            )
        })?;
    if material_set.get("materialEncoding").and_then(Value::as_str)
        != Some("binary-chunked-full-public-setup-commitment-values")
    {
        return Ok(Ok(()));
    }
    let transport = match material_set.get("transport") {
        Some(value) => value,
        None => {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceMissing",
                "binary-chunked vssCoefficientCommitmentMaterial must include transport metadata bound to the setup transport certificate",
                "setupPackage.vssCoefficientCommitmentMaterial.transport",
            )));
        }
    };
    let Some(transport_object) = transport.as_object() else {
        return Ok(Err(Refusal::new(
            "vssMaterialTransportReferenceNotObject",
            "vssCoefficientCommitmentMaterial.transport must be an object",
            "setupPackage.vssCoefficientCommitmentMaterial.transport",
        )));
    };
    for (field_name, expected_value) in [
        ("chunkSizeBytes", SETUP_TRANSPORT_CHUNK_SIZE_BYTES),
        ("chunkCount", expected_chunk_count),
        ("totalByteLength", expected_byte_length),
    ] {
        match transport_object.get(field_name).and_then(Value::as_u64) {
            Some(observed_value) if observed_value == expected_value => {}
            Some(_) => {
                return Ok(Err(Refusal::new(
                    "vssMaterialTransportReferenceMetadataMismatch",
                    "vssCoefficientCommitmentMaterial.transport numeric metadata must match the setup transport certificate",
                    format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
                )));
            }
            None => {
                return Ok(Err(Refusal::new(
                    "vssMaterialTransportReferenceMetadataMissing",
                    format!("vssCoefficientCommitmentMaterial.transport.{field_name} is required"),
                    format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
                )));
            }
        }
    }
    for (field_name, expected_value) in [
        ("fullObjectHash", expected_full_object_hash),
        ("chunkRoot", expected_chunk_root),
    ] {
        let Some(observed_value) = transport_object.get(field_name).and_then(Value::as_str) else {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceHashMissing",
                format!("vssCoefficientCommitmentMaterial.transport.{field_name} is required"),
                format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
            )));
        };
        validate_hash_string(
            observed_value,
            &format!("vssCoefficientCommitmentMaterial.transport.{field_name}"),
        )?;
        if observed_value != expected_value {
            return Ok(Err(Refusal::new(
                "vssMaterialTransportReferenceHashMismatch",
                "vssCoefficientCommitmentMaterial.transport hash metadata must match the setup transport certificate",
                format!("setupPackage.vssCoefficientCommitmentMaterial.transport.{field_name}"),
            )));
        }
    }

    Ok(Ok(()))
}

pub(super) fn transport_chunk_hashes(
    transport_certificate: &Value,
    expected_chunk_count: usize,
) -> CanonicalResult<Result<Vec<String>, Refusal>> {
    transport_hashes_at(
        transport_certificate,
        "chunkHashes",
        expected_chunk_count,
        "setupPackage.setupTransportCertificate",
    )
}

pub(super) fn transport_hashes_at(
    value: &Value,
    field_name: &'static str,
    expected_chunk_count: usize,
    object_path: &str,
) -> CanonicalResult<Result<Vec<String>, Refusal>> {
    match transport_hash_array(value, field_name, object_path, Some(expected_chunk_count)) {
        Ok(value) => Ok(Ok(value)),
        Err(refusal) => Ok(Err(refusal)),
    }
}

fn transport_hash_array(
    value: &Value,
    field_name: &'static str,
    object_path: &str,
    expected_chunk_count: Option<usize>,
) -> Result<Vec<String>, Refusal> {
    let chunk_hash_values = match value.get(field_name).and_then(Value::as_array) {
        Some(value) => value,
        None => {
            return Err(Refusal::new(
                "transportChunkHashesMissing",
                format!("{object_path}.{field_name} must list every setup transport chunk hash"),
                format!("{object_path}.{field_name}"),
            ));
        }
    };
    if let Some(expected_chunk_count) = expected_chunk_count
        && chunk_hash_values.len() != expected_chunk_count
    {
        return Err(Refusal::new(
            "transportChunkHashCountMismatch",
            format!("{object_path}.{field_name} length must match chunkCount"),
            format!("{object_path}.{field_name}"),
        ));
    }
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    let mut seen_chunk_hashes = BTreeSet::new();
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(Refusal::new(
                "transportChunkHashNotString",
                format!("{object_path}.{field_name} entries must be protocol hashes"),
                format!("{object_path}.{field_name}[{chunk_index}]"),
            ));
        };
        if chunk_hash.len() != 128
            || !chunk_hash
                .chars()
                .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
        {
            return Err(Refusal::new(
                "transportChunkHashInvalid",
                format!("{object_path}.{field_name} entries must be protocol hashes"),
                format!("{object_path}.{field_name}[{chunk_index}]"),
            ));
        }
        if !seen_chunk_hashes.insert(chunk_hash.to_string()) {
            return Err(Refusal::new(
                "transportChunkHashDuplicate",
                format!("{object_path}.{field_name} must not contain duplicate chunk hashes"),
                format!("{object_path}.{field_name}"),
            ));
        }
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(chunk_hashes)
}

pub(super) fn setup_transport_expected_hash_array(
    value: &Value,
    field_name: &str,
    object_path: &str,
) -> CanonicalResult<Vec<String>> {
    let chunk_hash_values = value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path}.{field_name} must list transported chunk hashes"),
            )
        })?;
    let mut chunk_hashes = Vec::with_capacity(chunk_hash_values.len());
    for (chunk_index, chunk_hash_value) in chunk_hash_values.iter().enumerate() {
        let Some(chunk_hash) = chunk_hash_value.as_str() else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{object_path}.{field_name}[{chunk_index}] must be a protocol hash"),
            ));
        };
        validate_hash_string(
            chunk_hash,
            &format!("{object_path}.{field_name}[{chunk_index}]"),
        )?;
        chunk_hashes.push(chunk_hash.to_string());
    }

    Ok(chunk_hashes)
}

pub(super) fn setup_transport_full_object_set_hash(
    transported_objects: &[SetupTransportedObjectBinding],
    total_byte_length: u64,
    chunk_count: u64,
    chunk_hashes: &[String],
) -> CanonicalResult<String> {
    let transported_object_values = transported_objects
        .iter()
        .map(|transported_object| {
            json!({
                "objectName": transported_object.object_name,
                "objectRole": transported_object.object_role,
                "objectRoot": transported_object.object_root,
                "byteLength": transported_object.byte_length,
                "chunkStartIndex": transported_object.chunk_start_index,
                "chunkCount": transported_object.chunk_count,
                "chunkRoot": transported_object.chunk_root,
                "fullObjectHash": transported_object.full_object_hash,
            })
        })
        .collect::<Vec<_>>();

    derive_protocol_hash(
        "SetupTransportFullObjectSetHash",
        &json!({
            "objectType": "SetupTransportFullObjectSet",
            "objectVersion": 1,
            "transportedObjects": transported_object_values,
            "totalByteLength": total_byte_length,
            "chunkCount": chunk_count,
            "chunkHashes": chunk_hashes,
        }),
    )
}

pub(in super::super) fn setup_transport_chunk_manifest_root(
    chunk_size_bytes: u64,
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> CanonicalResult<String> {
    derive_protocol_hash(
        "SetupTransportChunkManifestRoot",
        &json!({
            "objectType": SETUP_TRANSPORT_CHUNK_MANIFEST_OBJECT_TYPE,
            "objectVersion": 1,
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )
}

pub(in super::super) fn setup_transport_vss_material_byte_length_for_roster(
    roster: &AcceptedRosterParameters,
    ring_degree: u64,
) -> CanonicalResult<u64> {
    let participant_count = roster.participant_count;
    let decryption_threshold = roster.decryption_threshold;
    let mut header = Vec::new();
    header.extend(b"SLVSSMAT");
    crate::encoding::append_varuint(&mut header, 1);
    crate::encoding::append_varuint(&mut header, participant_count);
    crate::encoding::append_varuint(&mut header, decryption_threshold);
    crate::encoding::append_varuint(&mut header, DATA_PRIMES.len() as u64);
    crate::encoding::append_varuint(&mut header, ring_degree);
    crate::encoding::append_varuint(
        &mut header,
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64,
    );
    crate::encoding::append_varuint(&mut header, SETUP_COMMITMENT_ROW_COUNT as u64);

    let coordinate_byte_length = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            (0..DATA_PRIMES.len()).flat_map(move |rns_limb_index| {
                (0..decryption_threshold).map(move |shamir_coefficient_index| {
                    let mut coordinate_bytes = Vec::new();
                    crate::encoding::append_varuint(
                        &mut coordinate_bytes,
                        source_trustee_roster_position,
                    );
                    crate::encoding::append_varuint(&mut coordinate_bytes, rns_limb_index as u64);
                    crate::encoding::append_varuint(
                        &mut coordinate_bytes,
                        shamir_coefficient_index,
                    );
                    coordinate_bytes.len() as u64
                })
            })
        })
        .sum::<u64>();
    let commitment_limb_byte_length = SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .iter()
        .map(|commitment_modulus_index| {
            let mut index_bytes = Vec::new();
            crate::encoding::append_varuint(&mut index_bytes, *commitment_modulus_index as u64);
            index_bytes.len() as u64 + 8 + (SETUP_COMMITMENT_ROW_COUNT as u64 * ring_degree * 8)
        })
        .sum::<u64>();
    let material_record_count = participant_count * DATA_PRIMES.len() as u64 * decryption_threshold;

    Ok(header.len() as u64
        + coordinate_byte_length
        + material_record_count * commitment_limb_byte_length)
}

pub(super) fn setup_transport_chunk_count(byte_length: u64) -> CanonicalResult<u64> {
    if SETUP_TRANSPORT_CHUNK_SIZE_BYTES == 0 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup transport chunk size must be positive",
        ));
    }
    Ok(byte_length.div_ceil(SETUP_TRANSPORT_CHUNK_SIZE_BYTES))
}
