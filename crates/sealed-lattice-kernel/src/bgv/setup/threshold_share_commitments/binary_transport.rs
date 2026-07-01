use super::*;

use crate::hashing::derive_canonical_object_hash;

#[derive(Debug, Clone)]
pub(crate) struct SetupVssMaterialTransportHashes {
    pub(crate) full_object_hash: String,
    pub(crate) chunk_hashes: Vec<String>,
    pub(crate) chunk_root: String,
    pub(crate) total_byte_length: u64,
}

pub(super) struct TransportedMaterialChunks {
    pub(super) manifest: TransportedMaterialManifest,
    pub(super) chunks: Vec<Vec<u8>>,
}

#[derive(Clone)]
pub(super) struct TransportedMaterialManifest {
    pub(super) full_object_hash: String,
    pub(super) chunk_hashes: Vec<String>,
    pub(super) chunk_root: String,
    pub(super) chunk_count: usize,
    pub(super) total_byte_length: u64,
}

#[derive(Clone)]
pub(super) struct TransportedMaterialStreamHeader {
    pub(super) chunk_count: usize,
    pub(super) total_byte_length: u64,
    pub(super) expected_manifest: Option<TransportedMaterialManifest>,
}

pub(super) trait BinaryMaterialReader {
    fn is_finished(&self) -> bool;

    fn read_exact_vec(&mut self, length: usize) -> CanonicalResult<Vec<u8>>;

    fn read_varuint(&mut self) -> CanonicalResult<u64> {
        let mut shift = 0_u32;
        let mut value = 0_u64;
        let mut consumed = Vec::new();

        for byte_index in 0..10 {
            let byte = self.read_exact_vec(1)?[0];
            consumed.push(byte);
            let payload = u64::from(byte & 0x7f);
            if byte_index == 9 && payload > 1 {
                return Err(invalid_threshold_commitment_input(
                    "binary varuint exceeds u64",
                ));
            }
            value |= payload << shift;

            if byte & 0x80 == 0 {
                let mut canonical = Vec::new();
                append_varuint(&mut canonical, value);
                if canonical != consumed {
                    return Err(invalid_threshold_commitment_input(
                        "binary varuint is not minimally encoded",
                    ));
                }
                return Ok(value);
            }

            shift += 7;
        }

        Err(invalid_threshold_commitment_input(
            "binary varuint is too long",
        ))
    }

    fn read_usize(&mut self, field_name: &str) -> CanonicalResult<usize> {
        usize::try_from(self.read_varuint()?).map_err(|_| {
            invalid_threshold_commitment_input(format!("{field_name} does not fit usize"))
        })
    }

    fn read_u64_le(&mut self, field_name: &str) -> CanonicalResult<u64> {
        let bytes = self.read_exact_vec(8)?;
        let array: [u8; 8] = bytes.try_into().map_err(|_| {
            invalid_threshold_commitment_input(format!("{field_name} is malformed"))
        })?;

        Ok(u64::from_le_bytes(array))
    }
}

pub(super) struct ChunkedMaterialReader<'a> {
    chunks: &'a [Vec<u8>],
    chunk_index: usize,
    chunk_offset: usize,
    bytes_read: u64,
    total_byte_length: u64,
}

impl<'a> ChunkedMaterialReader<'a> {
    pub(super) fn new(chunks: &'a [Vec<u8>]) -> CanonicalResult<Self> {
        let total_byte_length = chunks.iter().try_fold(0_u64, |accumulator, chunk| {
            let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
                invalid_threshold_commitment_input("transport chunk length does not fit u64")
            })?;
            accumulator.checked_add(chunk_length).ok_or_else(|| {
                invalid_threshold_commitment_input("transport byte length overflowed")
            })
        })?;

        Ok(Self {
            chunks,
            chunk_index: 0,
            chunk_offset: 0,
            bytes_read: 0,
            total_byte_length,
        })
    }

    fn is_finished(&self) -> bool {
        self.bytes_read == self.total_byte_length
    }

    fn read_exact_vec(&mut self, length: usize) -> CanonicalResult<Vec<u8>> {
        let mut output = Vec::with_capacity(length);
        let mut remaining = length;
        while remaining > 0 {
            let Some(chunk) = self.chunks.get(self.chunk_index) else {
                return Err(invalid_threshold_commitment_input(
                    "transported material ended before the binary object was complete",
                ));
            };
            let available = chunk.len().saturating_sub(self.chunk_offset);
            if available == 0 {
                self.chunk_index += 1;
                self.chunk_offset = 0;
                continue;
            }
            let copied = available.min(remaining);
            output.extend_from_slice(&chunk[self.chunk_offset..self.chunk_offset + copied]);
            self.chunk_offset += copied;
            self.bytes_read = self
                .bytes_read
                .checked_add(u64::try_from(copied).map_err(|_| {
                    invalid_threshold_commitment_input("transport read length does not fit u64")
                })?)
                .ok_or_else(|| invalid_threshold_commitment_input("transport read overflowed"))?;
            remaining -= copied;
        }

        Ok(output)
    }
}

impl BinaryMaterialReader for ChunkedMaterialReader<'_> {
    fn is_finished(&self) -> bool {
        self.is_finished()
    }

    fn read_exact_vec(&mut self, length: usize) -> CanonicalResult<Vec<u8>> {
        self.read_exact_vec(length)
    }
}

pub(super) struct SliceMaterialReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceMaterialReader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl BinaryMaterialReader for SliceMaterialReader<'_> {
    fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn read_exact_vec(&mut self, length: usize) -> CanonicalResult<Vec<u8>> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid_threshold_commitment_input("transport slice read overflowed"))?;
        if end > self.bytes.len() {
            return Err(invalid_threshold_commitment_input(
                "transported material ended before the binary object was complete",
            ));
        }
        let output = self.bytes[self.offset..end].to_vec();
        self.offset = end;

        Ok(output)
    }
}

pub(super) enum PendingRead<T> {
    Ready(T),
    NeedMore,
}

pub(super) fn try_read_varuint_from_pending(
    bytes: &[u8],
    cursor: &mut usize,
) -> CanonicalResult<PendingRead<u64>> {
    let start_cursor = *cursor;
    let mut local_cursor = start_cursor;
    let mut shift = 0_u32;
    let mut value = 0_u64;
    let mut consumed = Vec::new();

    for byte_index in 0..10 {
        let Some(byte) = bytes.get(local_cursor).copied() else {
            return Ok(PendingRead::NeedMore);
        };
        local_cursor += 1;
        consumed.push(byte);
        let payload = u64::from(byte & 0x7f);
        if byte_index == 9 && payload > 1 {
            return Err(invalid_threshold_commitment_input(
                "binary varuint exceeds u64",
            ));
        }
        value |= payload << shift;

        if byte & 0x80 == 0 {
            let mut canonical = Vec::new();
            append_varuint(&mut canonical, value);
            if canonical != consumed {
                return Err(invalid_threshold_commitment_input(
                    "binary varuint is not minimally encoded",
                ));
            }
            *cursor = local_cursor;
            return Ok(PendingRead::Ready(value));
        }

        shift += 7;
    }

    Err(invalid_threshold_commitment_input(
        "binary varuint is too long",
    ))
}

pub(super) fn vss_material_record_count(
    participant_count: u64,
    decryption_threshold: usize,
) -> usize {
    participant_count as usize * DATA_PRIMES.len() * decryption_threshold
}

pub(super) fn vss_material_binary_record_length(ring_degree: usize) -> CanonicalResult<usize> {
    let row_coefficient_bytes = SETUP_COMMITMENT_ROW_COUNT
        .checked_mul(ring_degree)
        .and_then(|coefficient_count| coefficient_count.checked_mul(8))
        .ok_or_else(|| {
            invalid_threshold_commitment_input("transported VSS material record length overflowed")
        })?;
    let commitment_limb_bytes = 1_usize
        .checked_add(8)
        .and_then(|prefix_bytes| prefix_bytes.checked_add(row_coefficient_bytes))
        .ok_or_else(|| {
            invalid_threshold_commitment_input("transported VSS material record length overflowed")
        })?;
    SETUP_COMMITMENT_MODULUS_LIMB_INDICES
        .len()
        .checked_mul(commitment_limb_bytes)
        .and_then(|limb_bytes| limb_bytes.checked_add(3))
        .ok_or_else(|| {
            invalid_threshold_commitment_input("transported VSS material record length overflowed")
        })
}

pub(super) fn expected_vss_material_record_coordinates(
    record_index: usize,
    decryption_threshold: usize,
) -> CanonicalResult<(u64, usize, u64)> {
    let records_per_source_trustee = DATA_PRIMES
        .len()
        .checked_mul(decryption_threshold)
        .ok_or_else(|| {
            invalid_threshold_commitment_input("transport material coordinate overflowed")
        })?;
    let source_trustee_roster_position = record_index / records_per_source_trustee;
    let record_within_source = record_index % records_per_source_trustee;
    let rns_limb_index = record_within_source / decryption_threshold;
    let shamir_coefficient_index = record_within_source % decryption_threshold;

    Ok((
        u64::try_from(source_trustee_roster_position).map_err(|_| {
            invalid_threshold_commitment_input("source trustee roster position does not fit u64")
        })?,
        rns_limb_index,
        u64::try_from(shamir_coefficient_index).map_err(|_| {
            invalid_threshold_commitment_input("Shamir coefficient index does not fit u64")
        })?,
    ))
}

pub(super) fn read_binary_setup_commitment(
    reader: &mut impl BinaryMaterialReader,
    expected_source_trustee_roster_position: u64,
    expected_rns_limb_index: usize,
    expected_rns_prime: u64,
    expected_shamir_coefficient_index: u64,
    expected_ring_degree: usize,
) -> CanonicalResult<SetupCommitmentValue> {
    if reader.read_varuint()? != expected_source_trustee_roster_position {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material source trustee order is not canonical",
        ));
    }
    if reader.read_varuint()? != expected_rns_limb_index as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material RNS limb order is not canonical",
        ));
    }
    if reader.read_varuint()? != expected_shamir_coefficient_index {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material Shamir coefficient order is not canonical",
        ));
    }
    let mut limbs = Vec::with_capacity(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len());
    for expected_commitment_modulus_index in SETUP_COMMITMENT_MODULUS_LIMB_INDICES {
        if reader.read_varuint()? != expected_commitment_modulus_index as u64 {
            return Err(invalid_threshold_commitment_input(
                "transported commitment modulus limb order is not canonical",
            ));
        }
        let modulus = reader.read_u64_le("commitment modulus")?;
        if DATA_PRIMES.get(expected_commitment_modulus_index) != Some(&modulus) {
            return Err(invalid_threshold_commitment_input(
                "transported commitment modulus does not match the commitment parameters",
            ));
        }
        let mut rows = Vec::with_capacity(SETUP_COMMITMENT_ROW_COUNT);
        for _row_index in 0..SETUP_COMMITMENT_ROW_COUNT {
            let mut row = Vec::with_capacity(expected_ring_degree);
            for _coefficient_index in 0..expected_ring_degree {
                let residue = reader.read_u64_le("commitment coefficient")?;
                if residue >= modulus {
                    return Err(invalid_threshold_commitment_input(
                        "transported commitment coefficient is not canonical modulo its limb",
                    ));
                }
                row.push(residue);
            }
            rows.push(row);
        }
        limbs.push(SetupCommitmentLimb {
            commitment_modulus_index: expected_commitment_modulus_index,
            modulus,
            rows,
        });
    }

    Ok(SetupCommitmentValue {
        source_rns_limb_index: expected_rns_limb_index,
        source_message_modulus: expected_rns_prime,
        shamir_coefficient_index: expected_shamir_coefficient_index,
        ring_degree: expected_ring_degree,
        limbs,
    })
}

pub(crate) fn setup_vss_material_transport_hashes(
    chunks: &[Vec<u8>],
    chunk_size_bytes: u64,
) -> CanonicalResult<SetupVssMaterialTransportHashes> {
    if chunk_size_bytes == 0 {
        return Err(invalid_threshold_commitment_input(
            "setup transport chunk size must be positive",
        ));
    }
    if chunks.is_empty() {
        return Err(invalid_threshold_commitment_input(
            "setup transport requires at least one material chunk",
        ));
    }
    let chunk_size_usize = usize::try_from(chunk_size_bytes).map_err(|_| {
        invalid_threshold_commitment_input("setup transport chunk size does not fit usize")
    })?;
    let total_byte_length =
        chunks
            .iter()
            .enumerate()
            .try_fold(0_u64, |accumulator, (chunk_index, chunk)| {
                if chunk.is_empty() {
                    return Err(invalid_threshold_commitment_input(
                        "setup transport chunks must be non-empty",
                    ));
                }
                if chunk.len() > chunk_size_usize {
                    return Err(invalid_threshold_commitment_input(
                        "setup transport chunk exceeds the accepted chunk size",
                    ));
                }
                if chunk_index + 1 < chunks.len() && chunk.len() != chunk_size_usize {
                    return Err(invalid_threshold_commitment_input(
                        "setup transport contains a short non-final chunk",
                    ));
                }
                let chunk_length = u64::try_from(chunk.len()).map_err(|_| {
                    invalid_threshold_commitment_input(
                        "setup transport chunk length does not fit u64",
                    )
                })?;
                accumulator.checked_add(chunk_length).ok_or_else(|| {
                    invalid_threshold_commitment_input("setup transport byte length overflowed")
                })
            })?;

    let full_object_hash = streaming_hash512_hex(
        "sealed-lattice/setup/vss-coefficient-commitment-material/full-object-v1",
        total_byte_length,
        chunks,
    )?;
    let mut chunk_hashes = Vec::with_capacity(chunks.len());
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        chunk_hashes.push(setup_vss_material_chunk_hash(chunk_index, chunk)?);
    }
    let chunk_root = setup_transport_chunk_manifest_root(
        chunk_size_bytes,
        u64::try_from(chunks.len()).map_err(|_| {
            invalid_threshold_commitment_input("setup transport chunk count does not fit u64")
        })?,
        total_byte_length,
        &chunk_hashes,
        &full_object_hash,
    )?;

    Ok(SetupVssMaterialTransportHashes {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        total_byte_length,
    })
}

pub(super) fn read_transport_material(value: &Value) -> CanonicalResult<TransportedMaterialChunks> {
    let manifest = read_transport_material_manifest(value)?;
    let chunk_values = array_field(value, "chunks")?;
    if chunk_values.len() != manifest.chunk_count {
        return Err(invalid_threshold_commitment_input(
            "transport chunks length must match chunkCount",
        ));
    }
    let chunks = chunk_values
        .iter()
        .enumerate()
        .map(|(expected_chunk_index, chunk_value)| {
            let chunk_object = chunk_value.as_object().ok_or_else(|| {
                invalid_threshold_commitment_input("transport chunk entries must be objects")
            })?;
            let observed_chunk_index = chunk_object
                .get("chunkIndex")
                .and_then(Value::as_u64)
                .ok_or_else(|| invalid_threshold_commitment_input("chunkIndex is required"))?;
            if observed_chunk_index != expected_chunk_index as u64 {
                return Err(invalid_threshold_commitment_input(
                    "transport chunks must be supplied in ascending chunk-index order",
                ));
            }
            let bytes_hex = chunk_object
                .get("bytesHex")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid_threshold_commitment_input("chunk bytesHex is required"))?;
            decode_hex(bytes_hex)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let observed_total_byte_length = chunks.iter().try_fold(0_u64, |accumulator, chunk| {
        accumulator
            .checked_add(u64::try_from(chunk.len()).map_err(|_| {
                invalid_threshold_commitment_input("transport chunk length does not fit u64")
            })?)
            .ok_or_else(|| invalid_threshold_commitment_input("transport byte length overflowed"))
    })?;
    if observed_total_byte_length != manifest.total_byte_length {
        return Err(invalid_threshold_commitment_input(
            "transport totalByteLength must match supplied chunk bytes",
        ));
    }

    Ok(TransportedMaterialChunks { manifest, chunks })
}

fn read_transport_material_manifest(value: &Value) -> CanonicalResult<TransportedMaterialManifest> {
    if value.get("objectType").and_then(Value::as_str) != Some(VSS_MATERIAL_BINARY_OBJECT_TYPE) {
        return Err(invalid_threshold_commitment_input(
            "transportedVssCoefficientCommitmentMaterial.objectType must be SetupTransportedVssCoefficientCommitmentMaterial",
        ));
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_threshold_commitment_input(
            "transportedVssCoefficientCommitmentMaterial.objectVersion must be 1",
        ));
    }
    if value.get("binaryFormat").and_then(Value::as_str) != Some(VSS_MATERIAL_BINARY_FORMAT) {
        return Err(invalid_threshold_commitment_input(
            "transported VSS coefficient material must use the accepted binary format",
        ));
    }
    if u64_field(value, "chunkSizeBytes")? != SETUP_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(invalid_threshold_commitment_input(
            "transported VSS coefficient material must use the accepted 1 MiB setup chunk size",
        ));
    }
    let expected_chunk_count = usize_field(value, "chunkCount")?;
    let expected_total_byte_length = u64_field(value, "totalByteLength")?;
    let full_object_hash = hash_string_field(value, "fullObjectHash")?.to_string();
    let chunk_root = hash_string_field(value, "chunkRoot")?.to_string();
    let chunk_hash_values = array_field(value, "chunkHashes")?;
    if chunk_hash_values.len() != expected_chunk_count {
        return Err(invalid_threshold_commitment_input(
            "transport chunkHashes length must match chunkCount",
        ));
    }
    let chunk_hashes = chunk_hash_values
        .iter()
        .enumerate()
        .map(|(chunk_index, chunk_hash_value)| {
            let Some(chunk_hash) = chunk_hash_value.as_str() else {
                return Err(invalid_threshold_commitment_input(format!(
                    "chunkHashes[{chunk_index}] must be a hash string"
                )));
            };
            validate_hash_string(chunk_hash, &format!("chunkHashes[{chunk_index}]"))?;
            Ok(chunk_hash.to_string())
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    if expected_chunk_count == 0 {
        return Err(invalid_threshold_commitment_input(
            "setup transport requires at least one material chunk",
        ));
    }
    validate_transport_manifest_shape(
        expected_chunk_count,
        expected_total_byte_length,
        &chunk_hashes,
        &full_object_hash,
        &chunk_root,
    )?;

    Ok(TransportedMaterialManifest {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        chunk_count: expected_chunk_count,
        total_byte_length: expected_total_byte_length,
    })
}

pub(super) fn read_transport_material_stream_header(
    value: &Value,
) -> CanonicalResult<TransportedMaterialStreamHeader> {
    if value.get("objectType").and_then(Value::as_str) != Some(VSS_MATERIAL_BINARY_OBJECT_TYPE) {
        return Err(invalid_threshold_commitment_input(
            "transportedVssCoefficientCommitmentMaterial.objectType must be SetupTransportedVssCoefficientCommitmentMaterial",
        ));
    }
    if value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_threshold_commitment_input(
            "transportedVssCoefficientCommitmentMaterial.objectVersion must be 1",
        ));
    }
    if value.get("binaryFormat").and_then(Value::as_str) != Some(VSS_MATERIAL_BINARY_FORMAT) {
        return Err(invalid_threshold_commitment_input(
            "transported VSS coefficient material must use the accepted binary format",
        ));
    }
    if u64_field(value, "chunkSizeBytes")? != SETUP_TRANSPORT_CHUNK_SIZE_BYTES {
        return Err(invalid_threshold_commitment_input(
            "transported VSS coefficient material must use the accepted 1 MiB setup chunk size",
        ));
    }
    let chunk_count = usize_field(value, "chunkCount")?;
    if chunk_count == 0 {
        return Err(invalid_threshold_commitment_input(
            "setup transport requires at least one material chunk",
        ));
    }
    let total_byte_length = u64_field(value, "totalByteLength")?;
    validate_transport_chunk_count_matches_total_byte_length(chunk_count, total_byte_length)?;
    let has_full_object_hash = value.get("fullObjectHash").is_some();
    let has_chunk_hashes = value.get("chunkHashes").is_some();
    let has_chunk_root = value.get("chunkRoot").is_some();
    let expected_manifest = if has_full_object_hash || has_chunk_hashes || has_chunk_root {
        if !(has_full_object_hash && has_chunk_hashes && has_chunk_root) {
            return Err(invalid_threshold_commitment_input(
                "transport stream expected manifest must include fullObjectHash, chunkHashes, and chunkRoot together",
            ));
        }
        let full_object_hash = hash_string_field(value, "fullObjectHash")?.to_string();
        let chunk_root = hash_string_field(value, "chunkRoot")?.to_string();
        let chunk_hash_values = array_field(value, "chunkHashes")?;
        if chunk_hash_values.len() != chunk_count {
            return Err(invalid_threshold_commitment_input(
                "transport chunkHashes length must match chunkCount",
            ));
        }
        let chunk_hashes = chunk_hash_values
            .iter()
            .enumerate()
            .map(|(chunk_index, chunk_hash_value)| {
                let Some(chunk_hash) = chunk_hash_value.as_str() else {
                    return Err(invalid_threshold_commitment_input(format!(
                        "chunkHashes[{chunk_index}] must be a hash string"
                    )));
                };
                validate_hash_string(chunk_hash, &format!("chunkHashes[{chunk_index}]"))?;
                Ok(chunk_hash.to_string())
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        validate_transport_manifest_shape(
            chunk_count,
            total_byte_length,
            &chunk_hashes,
            &full_object_hash,
            &chunk_root,
        )?;
        Some(TransportedMaterialManifest {
            full_object_hash,
            chunk_hashes,
            chunk_root,
            chunk_count,
            total_byte_length,
        })
    } else {
        None
    };

    Ok(TransportedMaterialStreamHeader {
        chunk_count,
        total_byte_length,
        expected_manifest,
    })
}

fn validate_transport_manifest_shape(
    chunk_count: usize,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
    chunk_root: &str,
) -> CanonicalResult<()> {
    if chunk_count == 0 {
        return Err(invalid_threshold_commitment_input(
            "setup transport requires at least one material chunk",
        ));
    }
    if chunk_hashes.len() != chunk_count {
        return Err(invalid_threshold_commitment_input(
            "transport chunkHashes length must match chunkCount",
        ));
    }
    validate_transport_chunk_count_matches_total_byte_length(chunk_count, total_byte_length)?;
    validate_hash_string(full_object_hash, "fullObjectHash")?;
    validate_hash_string(chunk_root, "chunkRoot")?;
    let expected_chunk_root = setup_transport_chunk_manifest_root(
        SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
        u64::try_from(chunk_count).map_err(|_| {
            invalid_threshold_commitment_input("setup transport chunk count does not fit u64")
        })?,
        total_byte_length,
        chunk_hashes,
        full_object_hash,
    )?;
    if expected_chunk_root != chunk_root {
        return Err(invalid_threshold_commitment_input(
            "transport chunkRoot does not match the canonical chunk manifest",
        ));
    }

    Ok(())
}

pub(super) fn validate_transport_chunk_count_matches_total_byte_length(
    chunk_count: usize,
    total_byte_length: u64,
) -> CanonicalResult<()> {
    if total_byte_length == 0 {
        return Err(invalid_threshold_commitment_input(
            "setup transport totalByteLength must be positive",
        ));
    }
    let expected_chunk_count_u64 = ((total_byte_length - 1) / SETUP_TRANSPORT_CHUNK_SIZE_BYTES) + 1;
    let expected_chunk_count = usize::try_from(expected_chunk_count_u64).map_err(|_| {
        invalid_threshold_commitment_input(
            "setup transport expected chunk count does not fit usize",
        )
    })?;
    if chunk_count != expected_chunk_count {
        return Err(invalid_threshold_commitment_input(
            "transport chunkCount must match totalByteLength and the accepted chunk size",
        ));
    }

    Ok(())
}

pub(super) fn compare_transport_hashes(
    transport: &TransportedMaterialChunks,
    hashes: &SetupVssMaterialTransportHashes,
) -> CanonicalResult<()> {
    compare_transport_manifest_hashes(&transport.manifest, hashes)
}

pub(super) fn compare_transport_manifest_hashes(
    transport: &TransportedMaterialManifest,
    hashes: &SetupVssMaterialTransportHashes,
) -> CanonicalResult<()> {
    if transport.full_object_hash != hashes.full_object_hash {
        return Err(invalid_threshold_commitment_input(
            "transport fullObjectHash does not match supplied chunk bytes",
        ));
    }
    if transport.chunk_hashes != hashes.chunk_hashes {
        return Err(invalid_threshold_commitment_input(
            "transport chunkHashes do not match supplied chunk bytes",
        ));
    }
    if transport.chunk_root != hashes.chunk_root {
        return Err(invalid_threshold_commitment_input(
            "transport chunkRoot does not match the canonical chunk manifest",
        ));
    }

    Ok(())
}

pub(super) fn setup_vss_material_chunk_hash(
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    let mut chunk_index_bytes = Vec::new();
    append_varuint(
        &mut chunk_index_bytes,
        u64::try_from(chunk_index).map_err(|_| {
            invalid_threshold_commitment_input("transport chunk index does not fit u64")
        })?,
    );

    Ok(hash512_hex(
        "sealed-lattice/setup/vss-coefficient-commitment-material/chunk-v1",
        &[&chunk_index_bytes, chunk],
    ))
}

pub(super) fn streaming_hash512_hex(
    domain: &str,
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> CanonicalResult<String> {
    let mut hasher = streaming_hash512_hasher(domain, total_byte_length);
    for chunk in chunks {
        hasher.update(chunk);
    }

    Ok(finalize_streaming_hash512_hex(hasher))
}

pub(super) fn streaming_hash512_hasher(domain: &str, total_byte_length: u64) -> Shake256 {
    let mut prefix = Vec::new();
    prefix.extend(HASH512_PREIMAGE_PREFIX);
    append_bytes(&mut prefix, domain.as_bytes());
    append_varuint(&mut prefix, 1);
    append_varuint(&mut prefix, total_byte_length);

    let mut hasher = Shake256::default();
    hasher.update(&prefix);

    hasher
}

pub(super) fn finalize_streaming_hash512_hex(hasher: Shake256) -> String {
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);

    to_hex(&output)
}

pub(super) fn setup_transport_chunk_manifest_root(
    chunk_size_bytes: u64,
    chunk_count: u64,
    total_byte_length: u64,
    chunk_hashes: &[String],
    full_object_hash: &str,
) -> CanonicalResult<String> {
    derive_canonical_object_hash(&json!({
        "objectType": SETUP_TRANSPORT_CHUNK_MANIFEST_OBJECT_TYPE,
        "objectVersion": 1,
        "chunkSizeBytes": chunk_size_bytes,
        "chunkCount": chunk_count,
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": full_object_hash,
    }))
}
