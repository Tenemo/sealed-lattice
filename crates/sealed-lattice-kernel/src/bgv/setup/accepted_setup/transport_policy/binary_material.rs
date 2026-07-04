use super::*;

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
