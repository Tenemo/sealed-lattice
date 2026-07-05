use super::*;

#[derive(Debug)]
pub(in crate::bgv::setup) struct PublicKeyShareMaterialTransportHashes {
    pub(in crate::bgv::setup) full_object_hash: String,
    pub(in crate::bgv::setup) chunk_hashes: Vec<String>,
    pub(in crate::bgv::setup) chunk_root: String,
    pub(in crate::bgv::setup) total_byte_length: u64,
}

pub(super) struct PublicKeyShareMaterialByteReader {
    pub(super) bytes: Vec<u8>,
    pub(super) offset: usize,
}

impl PublicKeyShareMaterialByteReader {
    pub(super) fn new(chunks: &[Vec<u8>]) -> CanonicalResult<Self> {
        let total_byte_length = chunks.iter().try_fold(0_usize, |byte_count, chunk| {
            byte_count.checked_add(chunk.len()).ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material byte length overflowed",
                )
            })
        })?;
        let mut bytes = Vec::with_capacity(total_byte_length);
        for chunk in chunks {
            bytes.extend_from_slice(chunk);
        }

        Ok(Self { bytes, offset: 0 })
    }

    pub(super) fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    pub(super) fn read_exact(&mut self, length: usize) -> CanonicalResult<&[u8]> {
        let end_offset = self.offset.checked_add(length).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material read offset overflowed",
            )
        })?;
        let Some(slice) = self.bytes.get(self.offset..end_offset) else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "transported public-key share material ended before the binary object was complete",
            ));
        };
        self.offset = end_offset;

        Ok(slice)
    }

    pub(super) fn read_varuint(&mut self, field_name: &str) -> CanonicalResult<u64> {
        let mut shift = 0_u32;
        let mut value = 0_u64;
        let mut consumed = Vec::new();
        for byte_index in 0..10 {
            let byte = self.read_exact(1)?[0];
            consumed.push(byte);
            let payload = u64::from(byte & 0x7f);
            if byte_index == 9 && payload > 1 {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    format!("{field_name} binary varuint exceeds u64"),
                ));
            }
            value |= payload << shift;
            if byte & 0x80 == 0 {
                let mut canonical = Vec::new();
                crate::encoding::append_varuint(&mut canonical, value);
                if canonical != consumed {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::InvalidFixture,
                        format!("{field_name} binary varuint is not minimally encoded"),
                    ));
                }

                return Ok(value);
            }
            shift += 7;
        }

        Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} binary varuint is too long"),
        ))
    }

    pub(super) fn read_u64_le(&mut self, field_name: &str) -> CanonicalResult<u64> {
        let bytes = self.read_exact(8)?;
        let byte_array: [u8; 8] = bytes.try_into().map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!("{field_name} is malformed"),
            )
        })?;

        Ok(u64::from_le_bytes(byte_array))
    }
}

pub(super) fn verify_public_key_share_material_transport_header(
    value: &Value,
) -> CanonicalResult<()> {
    if !value.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial must be an object",
        ));
    }
    if value.get("objectType").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_TRANSPORT_OBJECT_TYPE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.objectType must be SetupTransportedPublicKeyShareMaterial",
        ));
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.objectVersion must be 1",
        ));
    }
    if value.get("binaryFormat").and_then(Value::as_str)
        != Some(PUBLIC_KEY_SHARE_MATERIAL_BINARY_FORMAT)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "transportedPublicKeyShareMaterial.binaryFormat must match the accepted public-key share material binary format",
        ));
    }

    Ok(())
}

pub(super) fn public_key_share_material_chunks(value: &Value) -> CanonicalResult<Vec<Vec<u8>>> {
    if value_u64(value, "chunkSizeBytes")? != SETUP_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunkSizeBytes must match the setup transport parameters",
        ));
    }
    let expected_chunk_count = usize::try_from(value_u64(value, "chunkCount")?).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunkCount does not fit usize",
        )
    })?;
    let chunk_values = array_value(value, "chunks")?;
    if chunk_values.len() != expected_chunk_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "transported public-key share material chunks length must match chunkCount",
        ));
    }
    let mut chunks = Vec::with_capacity(expected_chunk_count);
    for (expected_chunk_index, chunk_value) in chunk_values.iter().enumerate() {
        if value_u64(chunk_value, "chunkIndex")?
            != u64::try_from(expected_chunk_index).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material chunk index does not fit u64",
                )
            })?
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "transported public-key share material chunks must be in ascending chunk-index order",
            ));
        }
        chunks.push(decode_hex(value_string(chunk_value, "bytesHex")?)?);
    }

    Ok(chunks)
}

pub(in crate::bgv::setup) fn public_key_share_material_transport_hashes(
    chunks: &[Vec<u8>],
) -> CanonicalResult<PublicKeyShareMaterialTransportHashes> {
    if chunks.is_empty() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public-key share material transport requires at least one chunk",
        ));
    }
    let chunk_size = usize::try_from(SETUP_TRANSPORT_CHUNK_SIZE_BYTES).map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "setup transport chunk size does not fit usize",
        )
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |byte_count, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::MalformedLength,
                        "public-key share material contains a short non-final chunk",
                    ));
                }
                byte_count
                    .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material chunk length does not fit u64",
                        )
                    })?)
                    .ok_or_else(|| {
                        CanonicalError::new(
                            CanonicalErrorCode::MalformedLength,
                            "public-key share material byte length overflowed",
                        )
                    })
            })?;
    let full_object_hash = public_key_share_material_full_object_hash(total_byte_length, chunks);
    let chunk_hashes = chunks
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk)| {
            public_key_share_material_chunk_hash(&full_object_hash, chunk_index, chunk)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        u64::try_from(chunk_hashes.len()).map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material chunk count does not fit u64",
            )
        })?,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    Ok(PublicKeyShareMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

pub(super) fn public_key_share_material_full_object_hash(
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> String {
    let total_length_bytes = total_byte_length.to_le_bytes();
    let mut parts = Vec::with_capacity(chunks.len() + 1);
    parts.push(total_length_bytes.as_slice());
    for chunk in chunks {
        parts.push(chunk.as_slice());
    }

    hash512_hex(
        "sealed-lattice/setup/public-key-share-material/full-object-v1",
        &parts,
    )
}

pub(super) fn public_key_share_material_chunk_hash(
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    let chunk_index_bytes = u64::try_from(chunk_index)
        .map_err(|_| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public-key share material chunk index does not fit u64",
            )
        })?
        .to_le_bytes();

    Ok(hash512_hex(
        "sealed-lattice/setup/public-key-share-material/chunk-v1",
        &[full_object_hash.as_bytes(), &chunk_index_bytes, chunk],
    ))
}

pub(super) fn verify_public_key_share_material_transport_hash_fields(
    value: &Value,
    transport_hashes: &PublicKeyShareMaterialTransportHashes,
    require_chunk_hashes: bool,
    value_name: &str,
) -> CanonicalResult<()> {
    let chunk_size = value_u64(value, "chunkSizeBytes")?;
    let chunk_count = value_u64(value, "chunkCount")?;
    let total_byte_length = value_u64(value, "totalByteLength")?;
    let full_object_hash = value_string(value, "fullObjectHash")?;
    let chunk_root = value_string(value, "chunkRoot")?;
    if chunk_size != SETUP_TRANSPORT_CHUNK_SIZE_BYTES
        || chunk_count
            != u64::try_from(transport_hashes.chunk_hashes.len()).map_err(|_| {
                CanonicalError::new(
                    CanonicalErrorCode::MalformedLength,
                    "public-key share material chunk count does not fit u64",
                )
            })?
        || total_byte_length != transport_hashes.total_byte_length
        || full_object_hash != transport_hashes.full_object_hash
        || chunk_root != transport_hashes.chunk_root
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            format!("{value_name} hash metadata does not match supplied chunks"),
        ));
    }
    if require_chunk_hashes {
        let chunk_hash_values = value
            .get("chunkHashes")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{value_name} must list every public-key share material chunk hash"),
                )
            })?;
        if chunk_hash_values.len() != transport_hashes.chunk_hashes.len() {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("{value_name} chunk hash count must match supplied chunks"),
            ));
        }
        for (chunk_hash_value, expected_chunk_hash) in chunk_hash_values
            .iter()
            .zip(transport_hashes.chunk_hashes.iter())
        {
            if chunk_hash_value.as_str() != Some(expected_chunk_hash.as_str()) {
                return Err(CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    format!("{value_name} chunk hashes must match supplied chunks"),
                ));
            }
        }
    }

    Ok(())
}

pub(super) fn verify_public_key_share_material_set_transport_reference(
    material_set: &Value,
    transport_hashes: &PublicKeyShareMaterialTransportHashes,
) -> CanonicalResult<()> {
    let transport = material_set.get("transport").ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.transport is required for binary-chunked material",
        )
    })?;
    if !transport.is_object() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "publicKeyShareMaterial.transport must be an object",
        ));
    }
    verify_public_key_share_material_transport_hash_fields(
        transport,
        transport_hashes,
        false,
        "public-key share material transport reference",
    )
}
