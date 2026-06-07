use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    bgv::{
        coefficient_codec::coefficient_vector_hash512,
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        validation::reject_unexpected_bgv_request_fields,
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint},
    hashing::{HASH512_PREIMAGE_PREFIX, derive_protocol_hash, hash512_hex, to_hex},
    transcript_core::decode_hex,
};

use super::{
    accepted_setup::{
        COLLECTIVE_BGV_SETUP_PROFILE_ID, accepted_q_share_hash, accepted_setup_profile_hash,
    },
    commitment::{
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_PROFILE_ID,
        SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentLimb, SetupCommitmentValue,
        add_scaled_setup_commitment_in_place, linear_combination_setup_commitments,
        parse_setup_commitment_full_value, setup_commitment_profile_hash, setup_commitment_root,
    },
    sharing::canonical_trustee_point,
    vss::carry_aware_vss_share_relation_profile_hash,
};

const FIRST_PROFILE_PARTICIPANT_COUNT: usize = 10;
const FIRST_PROFILE_DECRYPTION_THRESHOLD: usize = 4;
const VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE: &str = "VssSourceTrusteeCoefficientCommitments";
const VSS_COEFFICIENT_COMMITMENT_OBJECT_TYPE: &str = "VssCoefficientCommitment";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE: &str = "VssCoefficientCommitmentMaterial";
const THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE: &str = "ThresholdShareCommitmentSet";
const THRESHOLD_SHARE_RECIPIENT_COMMITMENT_OBJECT_TYPE: &str = "TrusteeThresholdShareCommitments";
const THRESHOLD_SHARE_LIMB_COMMITMENT_OBJECT_TYPE: &str = "ThresholdShareCommitment";
const THRESHOLD_SHARE_DERIVATION_RULE: &str =
    "sum-source-trustee-polynomial-commitments-at-trustee-point";
const SETUP_TRANSPORT_PROFILE_ID: &str = "sealed-lattice-setup-binary-chunked-transport-v1";
const SETUP_TRANSPORT_CHUNK_MANIFEST_OBJECT_TYPE: &str = "SetupTransportChunkManifest";
const SETUP_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
const VSS_MATERIAL_BINARY_OBJECT_TYPE: &str = "SetupTransportedVssCoefficientCommitmentMaterial";
const VSS_MATERIAL_BINARY_FORMAT: &str =
    "sealed-lattice-vss-coefficient-commitment-material-binary-v1";
const VSS_MATERIAL_BINARY_MAGIC: &[u8] = b"SLVSSMAT";
const VSS_MATERIAL_BINARY_VERSION: u64 = 1;

#[derive(Debug, Clone)]
pub(crate) struct SetupVssMaterialTransportHashes {
    pub(crate) full_object_hash: String,
    pub(crate) chunk_hashes: Vec<String>,
    pub(crate) chunk_root: String,
    pub(crate) total_byte_length: u64,
}

pub(crate) struct VerifiedTransportedConstantVssCommitments {
    pub(crate) material_set: Value,
    pub(crate) constant_commitments_by_source_trustee: BTreeMap<u64, Vec<SetupCommitmentValue>>,
}

#[derive(Clone)]
struct SourceTrusteeCommitmentBinding {
    source_trustee_identity: String,
    source_trustee_roster_position: u64,
    coefficient_commitment_roots: BTreeMap<(usize, u64), String>,
}

#[derive(Clone)]
struct CoefficientCommitmentBinding {
    source_trustee_roster_position: u64,
    rns_limb_index: usize,
    shamir_coefficient_index: u64,
    commitment_root: String,
    commitment: SetupCommitmentValue,
}

struct ThresholdLimbCommitment {
    rns_limb_index: usize,
    rns_prime: u64,
    threshold_share_commitment_root: String,
    coefficient_commitment_roots: Vec<String>,
    commitment: SetupCommitmentValue,
}

pub(crate) fn derive_threshold_share_commitments_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupContext",
            "publicMatrixSeedHash",
            "sourceTrusteeCoefficientCommitmentRecords",
            "coefficientCommitments",
        ],
        "deriveThresholdShareCommitments",
    )?;

    let setup_context = object_field(request, "setupContext")?;
    let public_matrix_seed_hash = hash_string_field(request, "publicMatrixSeedHash")?;
    let source_trustee_record_values =
        array_field(request, "sourceTrusteeCoefficientCommitmentRecords")?;
    let commitment_material_values = array_field(request, "coefficientCommitments")?;

    let threshold_share_commitments = derive_threshold_share_commitment_set_from_parts(
        setup_context,
        public_matrix_seed_hash,
        source_trustee_record_values,
        commitment_material_values,
    )?;
    let ring_degree = threshold_share_commitments
        .get("ringDegree")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "threshold share commitment set ring degree was not derived",
            )
        })?;
    let ring_degree_status = threshold_share_commitments
        .get("ringDegreeStatus")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "threshold share commitment set ring degree status was not derived",
            )
        })?;
    let threshold_share_commitment_root = threshold_share_commitments
        .get("thresholdShareCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "threshold share commitment set root was not derived",
            )
        })?;

    Ok(json!({
        "ok": true,
        "operation": "deriveThresholdShareCommitments",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "derivedLimbCommitmentCount": FIRST_PROFILE_PARTICIPANT_COUNT * DATA_PRIMES.len(),
        "thresholdShareCommitmentRoot": threshold_share_commitment_root,
        "thresholdShareCommitments": threshold_share_commitments,
    }))
}

pub(crate) fn derive_threshold_share_commitments_from_transport_request(
    request: &Value,
) -> CanonicalResult<Value> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupContext",
            "publicMatrixSeedHash",
            "vssCoefficientCommitmentRoot",
            "sourceTrusteeCoefficientCommitmentRecords",
            "transportedVssCoefficientCommitmentMaterial",
        ],
        "deriveThresholdShareCommitmentsFromTransport",
    )?;

    let setup_context = object_field(request, "setupContext")?;
    let public_matrix_seed_hash = hash_string_field(request, "publicMatrixSeedHash")?;
    let vss_coefficient_commitment_root =
        hash_string_field(request, "vssCoefficientCommitmentRoot")?;
    let source_trustee_record_values =
        array_field(request, "sourceTrusteeCoefficientCommitmentRecords")?;
    let transported_material =
        object_field(request, "transportedVssCoefficientCommitmentMaterial")?;

    verify_setup_context(setup_context)?;
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let source_trustee_bindings = verify_source_trustee_commitment_records(
        source_trustee_record_values,
        setup_context,
        public_matrix_seed_hash,
    )?;
    let transport = read_transport_material(transported_material)?;
    let hashes =
        setup_vss_material_transport_hashes(&transport.chunks, SETUP_TRANSPORT_CHUNK_SIZE_BYTES)?;
    compare_transport_hashes(&transport, &hashes)?;

    let derivation = derive_threshold_share_commitment_set_from_transport_bytes(
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_bindings,
        &transport.chunks,
    )?;
    let material_record_count =
        FIRST_PROFILE_PARTICIPANT_COUNT * DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD;
    let material_set = transported_vss_material_set_value(
        setup_context,
        public_matrix_seed_hash,
        derivation.ring_degree,
        derivation.ring_degree_status,
        material_record_count,
        vss_coefficient_commitment_root,
        &hashes,
    )?;
    let threshold_share_commitment_root = derivation
        .threshold_share_commitments
        .get("thresholdShareCommitmentRoot")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "transport derivation did not return a threshold root",
            )
        })?;

    Ok(json!({
        "ok": true,
        "operation": "deriveThresholdShareCommitmentsFromTransport",
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "materialBinaryFormat": VSS_MATERIAL_BINARY_FORMAT,
        "ringDegree": derivation.ring_degree,
        "ringDegreeStatus": derivation.ring_degree_status,
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "derivedLimbCommitmentCount": FIRST_PROFILE_PARTICIPANT_COUNT * DATA_PRIMES.len(),
        "transport": {
            "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": hashes.chunk_hashes.len(),
            "totalByteLength": hashes.total_byte_length,
            "fullObjectHash": hashes.full_object_hash,
            "chunkRoot": hashes.chunk_root,
            "chunkHashes": hashes.chunk_hashes,
        },
        "vssCoefficientCommitmentMaterial": material_set,
        "thresholdShareCommitmentRoot": threshold_share_commitment_root,
        "thresholdShareCommitments": derivation.threshold_share_commitments,
    }))
}

pub(crate) fn verify_constant_vss_commitments_from_transport_request(
    request: &Value,
) -> CanonicalResult<VerifiedTransportedConstantVssCommitments> {
    reject_unexpected_bgv_request_fields(
        request,
        &[
            "setupContext",
            "publicMatrixSeedHash",
            "vssCoefficientCommitmentRoot",
            "sourceTrusteeCoefficientCommitmentRecords",
            "transportedVssCoefficientCommitmentMaterial",
        ],
        "verifyConstantVssCommitmentsFromTransport",
    )?;

    let setup_context = object_field(request, "setupContext")?;
    let public_matrix_seed_hash = hash_string_field(request, "publicMatrixSeedHash")?;
    let vss_coefficient_commitment_root =
        hash_string_field(request, "vssCoefficientCommitmentRoot")?;
    let source_trustee_record_values =
        array_field(request, "sourceTrusteeCoefficientCommitmentRecords")?;
    let transported_material =
        object_field(request, "transportedVssCoefficientCommitmentMaterial")?;

    verify_setup_context(setup_context)?;
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let source_trustee_bindings = verify_source_trustee_commitment_records(
        source_trustee_record_values,
        setup_context,
        public_matrix_seed_hash,
    )?;
    let transport = read_transport_material(transported_material)?;
    let hashes =
        setup_vss_material_transport_hashes(&transport.chunks, SETUP_TRANSPORT_CHUNK_SIZE_BYTES)?;
    compare_transport_hashes(&transport, &hashes)?;

    let constant_material = read_constant_vss_commitments_from_transport_bytes(
        &source_trustee_bindings,
        &transport.chunks,
    )?;
    let material_record_count =
        FIRST_PROFILE_PARTICIPANT_COUNT * DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD;
    let material_set = transported_vss_material_set_value(
        setup_context,
        public_matrix_seed_hash,
        constant_material.ring_degree,
        constant_material.ring_degree_status,
        material_record_count,
        vss_coefficient_commitment_root,
        &hashes,
    )?;

    Ok(VerifiedTransportedConstantVssCommitments {
        material_set,
        constant_commitments_by_source_trustee: constant_material
            .constant_commitments_by_source_trustee,
    })
}

pub(crate) fn derive_threshold_share_commitment_set_from_parts(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_record_values: &[Value],
    commitment_material_values: &[Value],
) -> CanonicalResult<Value> {
    verify_setup_context(setup_context)?;
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let source_trustee_bindings = verify_source_trustee_commitment_records(
        source_trustee_record_values,
        setup_context,
        public_matrix_seed_hash,
    )?;
    let coefficient_commitments = verify_coefficient_commitment_material(
        commitment_material_values,
        setup_context,
        public_matrix_seed_hash,
        &source_trustee_bindings,
    )?;

    let ring_degree = coefficient_commitments
        .values()
        .next()
        .map(|binding| binding.commitment.ring_degree)
        .ok_or_else(|| invalid_threshold_commitment_input("no coefficient commitments supplied"))?;
    let ring_degree_status = if ring_degree == POLYNOMIAL_DEGREE {
        "profile-ring"
    } else {
        "development-reduced-ring"
    };

    let threshold_share_commitments = threshold_share_commitment_set(
        setup_context,
        public_matrix_seed_hash,
        ring_degree,
        ring_degree_status,
        &source_trustee_bindings,
        &coefficient_commitments,
    )?;

    Ok(threshold_share_commitments)
}

struct TransportedMaterialChunks {
    full_object_hash: String,
    chunk_hashes: Vec<String>,
    chunk_root: String,
    chunks: Vec<Vec<u8>>,
}

struct TransportThresholdDerivation {
    ring_degree: usize,
    ring_degree_status: &'static str,
    threshold_share_commitments: Value,
}

struct TransportConstantVssMaterial {
    ring_degree: usize,
    ring_degree_status: &'static str,
    constant_commitments_by_source_trustee: BTreeMap<u64, Vec<SetupCommitmentValue>>,
}

struct TransportThresholdAccumulator {
    coefficient_commitment_roots: Vec<String>,
    commitment: SetupCommitmentValue,
}

struct ChunkedMaterialReader<'a> {
    chunks: &'a [Vec<u8>],
    chunk_index: usize,
    chunk_offset: usize,
    bytes_read: u64,
    total_byte_length: u64,
}

impl<'a> ChunkedMaterialReader<'a> {
    fn new(chunks: &'a [Vec<u8>]) -> CanonicalResult<Self> {
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
        chunk_hashes.push(setup_vss_material_chunk_hash(
            &full_object_hash,
            chunk_index,
            chunk,
        )?);
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

fn read_transport_material(value: &Value) -> CanonicalResult<TransportedMaterialChunks> {
    reject_unexpected_transport_material_fields(value)?;
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
    let chunk_values = array_field(value, "chunks")?;
    if chunk_values.len() != expected_chunk_count {
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
    if observed_total_byte_length != expected_total_byte_length {
        return Err(invalid_threshold_commitment_input(
            "transport totalByteLength must match supplied chunk bytes",
        ));
    }

    Ok(TransportedMaterialChunks {
        full_object_hash,
        chunk_hashes,
        chunk_root,
        chunks,
    })
}

fn reject_unexpected_transport_material_fields(value: &Value) -> CanonicalResult<()> {
    let Some(object) = value.as_object() else {
        return Err(invalid_threshold_commitment_input(
            "transportedVssCoefficientCommitmentMaterial must be an object",
        ));
    };
    for field_name in object.keys() {
        if ![
            "objectType",
            "objectVersion",
            "binaryFormat",
            "chunkSizeBytes",
            "chunkCount",
            "totalByteLength",
            "fullObjectHash",
            "chunkHashes",
            "chunkRoot",
            "chunks",
        ]
        .contains(&field_name.as_str())
        {
            return Err(invalid_threshold_commitment_input(format!(
                "transportedVssCoefficientCommitmentMaterial contains unexpected field {field_name}"
            )));
        }
    }

    Ok(())
}

fn compare_transport_hashes(
    transport: &TransportedMaterialChunks,
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

fn setup_vss_material_chunk_hash(
    full_object_hash: &str,
    chunk_index: usize,
    chunk: &[u8],
) -> CanonicalResult<String> {
    validate_hash_string(full_object_hash, "transport fullObjectHash")?;
    let mut chunk_index_bytes = Vec::new();
    append_varuint(
        &mut chunk_index_bytes,
        u64::try_from(chunk_index).map_err(|_| {
            invalid_threshold_commitment_input("transport chunk index does not fit u64")
        })?,
    );

    Ok(hash512_hex(
        "sealed-lattice/setup/vss-coefficient-commitment-material/chunk-v1",
        &[full_object_hash.as_bytes(), &chunk_index_bytes, chunk],
    ))
}

fn streaming_hash512_hex(
    domain: &str,
    total_byte_length: u64,
    chunks: &[Vec<u8>],
) -> CanonicalResult<String> {
    let mut prefix = Vec::new();
    prefix.extend(HASH512_PREIMAGE_PREFIX);
    append_bytes(&mut prefix, domain.as_bytes());
    append_varuint(&mut prefix, 1);
    append_varuint(&mut prefix, total_byte_length);

    let mut hasher = Shake256::default();
    hasher.update(&prefix);
    for chunk in chunks {
        hasher.update(chunk);
    }
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 64];
    reader.read(&mut output);

    Ok(to_hex(&output))
}

fn setup_transport_chunk_manifest_root(
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
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
            "chunkSizeBytes": chunk_size_bytes,
            "chunkCount": chunk_count,
            "totalByteLength": total_byte_length,
            "chunkHashes": chunk_hashes,
            "fullObjectHash": full_object_hash,
        }),
    )
}

fn read_constant_vss_commitments_from_transport_bytes(
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    chunks: &[Vec<u8>],
) -> CanonicalResult<TransportConstantVssMaterial> {
    let mut reader = ChunkedMaterialReader::new(chunks)?;
    let magic = reader.read_exact_vec(VSS_MATERIAL_BINARY_MAGIC.len())?;
    if magic != VSS_MATERIAL_BINARY_MAGIC {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material binary magic does not match",
        ));
    }
    if reader.read_varuint()? != VSS_MATERIAL_BINARY_VERSION {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material binary version is unsupported",
        ));
    }
    if reader.read_varuint()? != FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material participant count does not match the accepted profile",
        ));
    }
    if reader.read_varuint()? != FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material threshold degree does not match the accepted profile",
        ));
    }
    if reader.read_varuint()? != DATA_PRIMES.len() as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material RNS limb count does not match Q_share",
        ));
    }
    let ring_degree = reader.read_usize("ringDegree")?;
    if reader.read_varuint()? != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material commitment limb count does not match the commitment profile",
        ));
    }
    if reader.read_varuint()? != SETUP_COMMITMENT_ROW_COUNT as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material row count does not match the commitment profile",
        ));
    }

    let mut constant_commitments_by_source_trustee =
        BTreeMap::<u64, Vec<SetupCommitmentValue>>::new();
    for source_trustee_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        let source_trustee_binding = source_trustee_bindings
            .get(&source_trustee_roster_position)
            .ok_or_else(|| {
                invalid_threshold_commitment_input(
                    "transport material is missing a source trustee binding",
                )
            })?;
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
                let commitment = read_binary_setup_commitment(
                    &mut reader,
                    source_trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    ring_degree,
                )?;
                let commitment_root = setup_commitment_root(&commitment)?;
                let expected_commitment_root = source_trustee_binding
                    .coefficient_commitment_roots
                    .get(&(rns_limb_index, shamir_coefficient_index))
                    .ok_or_else(|| {
                        invalid_threshold_commitment_input(
                            "transport material coordinate is absent from the source trustee record",
                        )
                    })?;
                if &commitment_root != expected_commitment_root {
                    return Err(invalid_threshold_commitment_input(
                        "transported setup commitment material does not match the source trustee commitment root",
                    ));
                }
                if shamir_coefficient_index == 0 {
                    constant_commitments_by_source_trustee
                        .entry(source_trustee_roster_position)
                        .or_default()
                        .push(commitment);
                }
            }
        }
    }
    if !reader.is_finished() {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material has trailing bytes after the final commitment record",
        ));
    }
    for source_trustee_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        if constant_commitments_by_source_trustee
            .get(&source_trustee_roster_position)
            .map(Vec::len)
            != Some(DATA_PRIMES.len())
        {
            return Err(invalid_threshold_commitment_input(
                "transported VSS material is missing a constant commitment limb",
            ));
        }
    }

    Ok(TransportConstantVssMaterial {
        ring_degree,
        ring_degree_status: if ring_degree == POLYNOMIAL_DEGREE {
            "profile-ring"
        } else {
            "development-reduced-ring"
        },
        constant_commitments_by_source_trustee,
    })
}

fn derive_threshold_share_commitment_set_from_transport_bytes(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    chunks: &[Vec<u8>],
) -> CanonicalResult<TransportThresholdDerivation> {
    let mut reader = ChunkedMaterialReader::new(chunks)?;
    let magic = reader.read_exact_vec(VSS_MATERIAL_BINARY_MAGIC.len())?;
    if magic != VSS_MATERIAL_BINARY_MAGIC {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material binary magic does not match",
        ));
    }
    if reader.read_varuint()? != VSS_MATERIAL_BINARY_VERSION {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material binary version is unsupported",
        ));
    }
    if reader.read_varuint()? != FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material participant count does not match the accepted profile",
        ));
    }
    if reader.read_varuint()? != FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material threshold degree does not match the accepted profile",
        ));
    }
    if reader.read_varuint()? != DATA_PRIMES.len() as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material RNS limb count does not match Q_share",
        ));
    }
    let ring_degree = reader.read_usize("ringDegree")?;
    if reader.read_varuint()? != SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len() as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material commitment limb count does not match the commitment profile",
        ));
    }
    if reader.read_varuint()? != SETUP_COMMITMENT_ROW_COUNT as u64 {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material row count does not match the commitment profile",
        ));
    }

    let mut accumulators = BTreeMap::<(u64, usize), TransportThresholdAccumulator>::new();
    for source_trustee_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        let source_trustee_binding = source_trustee_bindings
            .get(&source_trustee_roster_position)
            .ok_or_else(|| {
                invalid_threshold_commitment_input(
                    "transport material is missing a source trustee binding",
                )
            })?;
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            for shamir_coefficient_index in 0..FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
                let commitment = read_binary_setup_commitment(
                    &mut reader,
                    source_trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    ring_degree,
                )?;
                let commitment_root = setup_commitment_root(&commitment)?;
                let expected_commitment_root = source_trustee_binding
                    .coefficient_commitment_roots
                    .get(&(rns_limb_index, shamir_coefficient_index))
                    .ok_or_else(|| {
                        invalid_threshold_commitment_input(
                            "transport material coordinate is absent from the source trustee record",
                        )
                    })?;
                if &commitment_root != expected_commitment_root {
                    return Err(invalid_threshold_commitment_input(
                        "transported setup commitment material does not match the source trustee commitment root",
                    ));
                }
                accumulate_transport_threshold_commitments(
                    setup_context,
                    public_matrix_seed_hash,
                    source_trustee_roster_position,
                    rns_limb_index,
                    rns_prime,
                    shamir_coefficient_index,
                    &commitment_root,
                    &commitment,
                    &mut accumulators,
                )?;
            }
        }
    }
    if !reader.is_finished() {
        return Err(invalid_threshold_commitment_input(
            "transported VSS material has trailing bytes after the final commitment record",
        ));
    }
    let ring_degree_status = if ring_degree == POLYNOMIAL_DEGREE {
        "profile-ring"
    } else {
        "development-reduced-ring"
    };
    let threshold_share_commitments = threshold_share_commitment_set_from_transport_accumulators(
        setup_context,
        public_matrix_seed_hash,
        ring_degree,
        ring_degree_status,
        &accumulators,
    )?;

    Ok(TransportThresholdDerivation {
        ring_degree,
        ring_degree_status,
        threshold_share_commitments,
    })
}

fn read_binary_setup_commitment(
    reader: &mut ChunkedMaterialReader<'_>,
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
                "transported commitment modulus does not match the commitment profile",
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

#[allow(clippy::too_many_arguments)]
fn accumulate_transport_threshold_commitments(
    _setup_context: &Value,
    _public_matrix_seed_hash: &str,
    _source_trustee_roster_position: u64,
    rns_limb_index: usize,
    rns_prime: u64,
    shamir_coefficient_index: u64,
    commitment_root: &str,
    commitment: &SetupCommitmentValue,
    accumulators: &mut BTreeMap<(u64, usize), TransportThresholdAccumulator>,
) -> CanonicalResult<()> {
    for recipient_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        let recipient_roster_position_usize =
            usize::try_from(recipient_roster_position).map_err(|_| {
                invalid_threshold_commitment_input("recipient roster position does not fit usize")
            })?;
        let trustee_point = canonical_trustee_point(recipient_roster_position_usize, rns_prime)?;
        let scalar = shamir_coefficient_scalars(trustee_point, FIRST_PROFILE_DECRYPTION_THRESHOLD)?
            [shamir_coefficient_index as usize];
        let accumulator_key = (recipient_roster_position, rns_limb_index);
        match accumulators.get_mut(&accumulator_key) {
            Some(accumulator) => {
                accumulator
                    .coefficient_commitment_roots
                    .push(commitment_root.to_string());
                add_scaled_setup_commitment_in_place(
                    &mut accumulator.commitment,
                    commitment,
                    scalar,
                )?;
            }
            None => {
                let mut scaled_commitment =
                    linear_combination_setup_commitments(&[(commitment, scalar)])?;
                scaled_commitment.shamir_coefficient_index = 0;
                accumulators.insert(
                    accumulator_key,
                    TransportThresholdAccumulator {
                        coefficient_commitment_roots: vec![commitment_root.to_string()],
                        commitment: scaled_commitment,
                    },
                );
            }
        }
    }

    Ok(())
}

fn threshold_share_commitment_set_from_transport_accumulators(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    ring_degree_status: &str,
    accumulators: &BTreeMap<(u64, usize), TransportThresholdAccumulator>,
) -> CanonicalResult<Value> {
    let mut recipient_records = Vec::with_capacity(FIRST_PROFILE_PARTICIPANT_COUNT);
    for recipient_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        let recipient_identity = format!("trustee-{recipient_roster_position}");
        let recipient_roster_position_usize =
            usize::try_from(recipient_roster_position).map_err(|_| {
                invalid_threshold_commitment_input("recipient roster position does not fit usize")
            })?;
        let mut limb_commitments = Vec::with_capacity(DATA_PRIMES.len());
        for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
            let accumulator = accumulators
                .get(&(recipient_roster_position, rns_limb_index))
                .ok_or_else(|| {
                    invalid_threshold_commitment_input(
                        "transport derivation is missing a threshold accumulator",
                    )
                })?;
            let expected_root_count =
                FIRST_PROFILE_PARTICIPANT_COUNT * FIRST_PROFILE_DECRYPTION_THRESHOLD;
            if accumulator.coefficient_commitment_roots.len() != expected_root_count {
                return Err(invalid_threshold_commitment_input(
                    "transport threshold accumulator does not contain every coefficient root",
                ));
            }
            let threshold_limb_without_root = ThresholdLimbCommitment {
                rns_limb_index,
                rns_prime,
                threshold_share_commitment_root: String::new(),
                coefficient_commitment_roots: accumulator.coefficient_commitment_roots.clone(),
                commitment: accumulator.commitment.clone(),
            };
            let threshold_share_commitment_root = derive_protocol_hash(
                "ThresholdShareCommitmentRoot",
                &threshold_limb_commitment_root_payload(
                    setup_context,
                    public_matrix_seed_hash,
                    &recipient_identity,
                    recipient_roster_position,
                    recipient_roster_position_usize,
                    &threshold_limb_without_root,
                )?,
            )?;
            let threshold_limb = ThresholdLimbCommitment {
                threshold_share_commitment_root,
                ..threshold_limb_without_root
            };
            limb_commitments.push(threshold_limb_commitment_value(
                setup_context,
                public_matrix_seed_hash,
                &recipient_identity,
                recipient_roster_position,
                recipient_roster_position_usize,
                ring_degree_status,
                &threshold_limb,
            )?);
        }
        let trustee_point =
            canonical_trustee_point(recipient_roster_position_usize, DATA_PRIMES[0])?;
        let mut recipient_record = json!({
            "objectType": THRESHOLD_SHARE_RECIPIENT_COMMITMENT_OBJECT_TYPE,
            "objectVersion": 1,
            "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
            "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
            "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "recipientIdentity": recipient_identity,
            "recipientRosterPosition": recipient_roster_position,
            "trusteePoint": trustee_point,
            "ringDegree": ring_degree,
            "ringDegreeStatus": ring_degree_status,
            "limbCommitments": limb_commitments,
        });
        copy_context_fields(&mut recipient_record, setup_context)?;
        let recipient_commitment_root =
            derive_protocol_hash("ThresholdShareCommitmentRoot", &recipient_record)?;
        recipient_record["recipientCommitmentRoot"] = json!(recipient_commitment_root);
        recipient_records.push(recipient_record);
    }

    let mut commitment_set = json!({
        "objectType": THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "thresholdDegree": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "recipientRecords": recipient_records,
    });
    copy_context_fields(&mut commitment_set, setup_context)?;
    let commitment_set_root =
        derive_protocol_hash("ThresholdShareCommitmentRoot", &commitment_set)?;
    commitment_set["thresholdShareCommitmentRoot"] = json!(commitment_set_root);

    Ok(commitment_set)
}

fn transported_vss_material_set_value(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    ring_degree_status: &str,
    material_record_count: usize,
    vss_coefficient_commitment_root: &str,
    hashes: &SetupVssMaterialTransportHashes,
) -> CanonicalResult<Value> {
    validate_hash_string(
        vss_coefficient_commitment_root,
        "vssCoefficientCommitmentRoot",
    )?;
    let mut material_set = json!({
        "objectType": "VssCoefficientCommitmentMaterialSet",
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "commitmentProfileHash": setup_commitment_profile_hash()?,
        "materialEncoding": "binary-chunked-full-public-setup-commitment-values",
        "binaryFormat": VSS_MATERIAL_BINARY_FORMAT,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "thresholdDegree": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "materialRecordCount": material_record_count,
        "transport": {
            "transportProfileId": SETUP_TRANSPORT_PROFILE_ID,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": hashes.chunk_hashes.len(),
            "totalByteLength": hashes.total_byte_length,
            "fullObjectHash": hashes.full_object_hash,
            "chunkRoot": hashes.chunk_root,
        },
    });
    copy_context_fields(&mut material_set, setup_context)?;
    let material_root =
        derive_protocol_hash("VssCoefficientCommitmentMaterialRoot", &material_set)?;
    material_set["vssCoefficientCommitmentMaterialRoot"] = json!(material_root);

    Ok(material_set)
}

fn verify_setup_context(setup_context: &Value) -> CanonicalResult<()> {
    for field_name in setup_context_field_names() {
        if setup_context.get(field_name).is_none() {
            return Err(invalid_threshold_commitment_input(format!(
                "setupContext.{field_name} is required"
            )));
        }
    }
    for field_name in [
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
    ] {
        let hash = hash_string_field(setup_context, field_name)?;
        validate_hash_string(hash, &format!("setupContext.{field_name}"))?;
    }
    string_field(setup_context, "ceremonyId")?;
    string_field(setup_context, "setupEpoch")?;

    if setup_context
        .get("setupProfileHash")
        .and_then(Value::as_str)
        != Some(accepted_setup_profile_hash()?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.setupProfileHash does not match CollectiveBgvSetup-v1",
        ));
    }
    if setup_context.get("qShareHash").and_then(Value::as_str)
        != Some(accepted_q_share_hash()?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.qShareHash does not match the accepted Q_share prime list",
        ));
    }
    if setup_context
        .get("carryAwareVssShareRelationProfileHash")
        .and_then(Value::as_str)
        != Some(carry_aware_vss_share_relation_profile_hash()?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.carryAwareVssShareRelationProfileHash does not match the accepted carry-aware VSS relation profile",
        ));
    }
    if setup_context
        .get("commitmentProfileHash")
        .and_then(Value::as_str)
        != Some(setup_commitment_profile_hash()?.as_str())
    {
        return Err(invalid_threshold_commitment_input(
            "setupContext.commitmentProfileHash does not match the accepted setup commitment profile",
        ));
    }

    Ok(())
}

fn verify_source_trustee_commitment_records(
    source_trustee_records: &[Value],
    setup_context: &Value,
    public_matrix_seed_hash: &str,
) -> CanonicalResult<BTreeMap<u64, SourceTrusteeCommitmentBinding>> {
    if source_trustee_records.len() != FIRST_PROFILE_PARTICIPANT_COUNT {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecords must contain one record for every accepted trustee",
        ));
    }

    let mut source_trustee_bindings = BTreeMap::new();
    for source_trustee_record in source_trustee_records {
        let source_trustee_binding = verify_source_trustee_commitment_record(
            source_trustee_record,
            setup_context,
            public_matrix_seed_hash,
        )?;
        if source_trustee_bindings
            .insert(
                source_trustee_binding.source_trustee_roster_position,
                source_trustee_binding,
            )
            .is_some()
        {
            return Err(invalid_threshold_commitment_input(
                "sourceTrusteeCoefficientCommitmentRecords contains duplicate source trustee roster positions",
            ));
        }
    }
    for roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        if !source_trustee_bindings.contains_key(&roster_position) {
            return Err(invalid_threshold_commitment_input(
                "sourceTrusteeCoefficientCommitmentRecords must cover the full accepted roster",
            ));
        }
    }

    Ok(source_trustee_bindings)
}

fn verify_source_trustee_commitment_record(
    source_trustee_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
) -> CanonicalResult<SourceTrusteeCommitmentBinding> {
    if source_trustee_record
        .get("objectType")
        .and_then(Value::as_str)
        != Some(VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE)
    {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.objectType must be VssSourceTrusteeCoefficientCommitments",
        ));
    }
    if source_trustee_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.objectVersion must be 1",
        ));
    }
    compare_context_fields(
        source_trustee_record,
        setup_context,
        "sourceTrusteeCoefficientCommitmentRecord",
    )?;
    if source_trustee_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.publicMatrixSeedHash must match publicMatrixSeedHash",
        ));
    }
    let source_trustee_identity =
        string_field(source_trustee_record, "sourceTrusteeIdentity")?.to_string();
    let source_trustee_roster_position =
        u64_field(source_trustee_record, "sourceTrusteeRosterPosition")?;
    if source_trustee_roster_position >= FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeRosterPosition is outside the accepted roster",
        ));
    }

    let coefficient_commitments = array_field(source_trustee_record, "coefficientCommitments")?;
    if coefficient_commitments.len() != DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCoefficientCommitmentRecord.coefficientCommitments must contain every Q_share limb and Shamir coefficient",
        ));
    }
    let mut seen_coordinates = BTreeSet::new();
    let mut coefficient_commitment_roots = BTreeMap::new();
    for coefficient_record in coefficient_commitments {
        let (rns_limb_index, shamir_coefficient_index, commitment_root) =
            verify_coefficient_record(
                coefficient_record,
                setup_context,
                public_matrix_seed_hash,
                &source_trustee_identity,
                source_trustee_roster_position,
            )?;
        if !seen_coordinates.insert((rns_limb_index, shamir_coefficient_index)) {
            return Err(invalid_threshold_commitment_input(
                "source trustee coefficient commitments must have distinct limb/coefficient coordinates",
            ));
        }
        coefficient_commitment_roots
            .insert((rns_limb_index, shamir_coefficient_index), commitment_root);
    }

    let source_trustee_commitment_root =
        hash_string_field(source_trustee_record, "sourceTrusteeCommitmentRoot")?;
    validate_hash_string(
        source_trustee_commitment_root,
        "sourceTrusteeCoefficientCommitmentRecord.sourceTrusteeCommitmentRoot",
    )?;
    let mut root_input = source_trustee_record.clone();
    root_input
        .as_object_mut()
        .expect("source trustee commitment record object was checked")
        .remove("sourceTrusteeCommitmentRoot");
    let expected_source_trustee_commitment_root =
        derive_protocol_hash("VssCoefficientCommitmentRoot", &root_input)?;
    if source_trustee_commitment_root != expected_source_trustee_commitment_root {
        return Err(invalid_threshold_commitment_input(
            "sourceTrusteeCommitmentRoot does not match the canonical source trustee coefficient commitment record",
        ));
    }

    Ok(SourceTrusteeCommitmentBinding {
        source_trustee_identity,
        source_trustee_roster_position,
        coefficient_commitment_roots,
    })
}

fn verify_coefficient_record(
    coefficient_record: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_identity: &str,
    source_trustee_roster_position: u64,
) -> CanonicalResult<(usize, u64, String)> {
    if coefficient_record.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_OBJECT_TYPE)
    {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment objectType must be VssCoefficientCommitment",
        ));
    }
    if coefficient_record
        .get("objectVersion")
        .and_then(Value::as_u64)
        != Some(1)
    {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment objectVersion must be 1",
        ));
    }
    compare_context_fields(coefficient_record, setup_context, "coefficientCommitment")?;
    if coefficient_record
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment publicMatrixSeedHash must match publicMatrixSeedHash",
        ));
    }
    if coefficient_record
        .get("sourceTrusteeIdentity")
        .and_then(Value::as_str)
        != Some(source_trustee_identity)
        || coefficient_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            != Some(source_trustee_roster_position)
    {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment source trustee binding must match its source trustee record",
        ));
    }
    let rns_limb_index = usize_field(coefficient_record, "rnsLimbIndex")?;
    let rns_prime = u64_field(coefficient_record, "rnsPrime")?;
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment rnsPrime must match Q_share at rnsLimbIndex",
        ));
    }
    let shamir_coefficient_index = u64_field(coefficient_record, "shamirCoefficientIndex")?;
    if shamir_coefficient_index >= FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
        return Err(invalid_threshold_commitment_input(
            "VSS coefficient commitment shamirCoefficientIndex is outside the accepted threshold degree",
        ));
    }
    let commitment_root = hash_string_field(coefficient_record, "commitmentRoot")?;
    validate_hash_string(commitment_root, "coefficientCommitment.commitmentRoot")?;
    for field_name in ["commitmentChunkRoot", "coefficientVectorHash512"] {
        validate_hash_string(
            hash_string_field(coefficient_record, field_name)?,
            &format!("coefficientCommitment.{field_name}"),
        )?;
    }

    Ok((
        rns_limb_index,
        shamir_coefficient_index,
        commitment_root.to_string(),
    ))
}

fn verify_coefficient_commitment_material(
    commitment_material_values: &[Value],
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
) -> CanonicalResult<BTreeMap<(u64, usize, u64), CoefficientCommitmentBinding>> {
    let expected_count =
        FIRST_PROFILE_PARTICIPANT_COUNT * DATA_PRIMES.len() * FIRST_PROFILE_DECRYPTION_THRESHOLD;
    if commitment_material_values.len() != expected_count {
        return Err(invalid_threshold_commitment_input(
            "coefficientCommitments must contain full public commitment material for every source trustee, Q_share limb, and Shamir coefficient",
        ));
    }

    let mut commitment_bindings = BTreeMap::new();
    let mut ring_degree: Option<usize> = None;
    for material_value in commitment_material_values {
        let commitment_binding = verify_coefficient_commitment_material_record(
            material_value,
            setup_context,
            public_matrix_seed_hash,
            source_trustee_bindings,
        )?;
        match ring_degree {
            Some(expected_ring_degree)
                if expected_ring_degree != commitment_binding.commitment.ring_degree =>
            {
                return Err(invalid_threshold_commitment_input(
                    "all coefficient commitments must use the same ring degree",
                ));
            }
            Some(_) => {}
            None => ring_degree = Some(commitment_binding.commitment.ring_degree),
        }

        let coordinate = (
            commitment_binding.source_trustee_roster_position,
            commitment_binding.rns_limb_index,
            commitment_binding.shamir_coefficient_index,
        );
        if commitment_bindings
            .insert(coordinate, commitment_binding)
            .is_some()
        {
            return Err(invalid_threshold_commitment_input(
                "coefficientCommitments contains duplicate source trustee/limb/coefficient material",
            ));
        }
    }

    for source_trustee_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        for rns_limb_index in 0..DATA_PRIMES.len() {
            for shamir_coefficient_index in 0..FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
                if !commitment_bindings.contains_key(&(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                )) {
                    return Err(invalid_threshold_commitment_input(
                        "coefficientCommitments must cover every accepted coordinate",
                    ));
                }
            }
        }
    }

    Ok(commitment_bindings)
}

fn verify_coefficient_commitment_material_record(
    material_value: &Value,
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
) -> CanonicalResult<CoefficientCommitmentBinding> {
    if material_value.get("objectType").and_then(Value::as_str)
        != Some(VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE)
    {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material objectType must be VssCoefficientCommitmentMaterial",
        ));
    }
    if material_value.get("objectVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material objectVersion must be 1",
        ));
    }
    compare_context_fields(
        material_value,
        setup_context,
        "coefficientCommitmentMaterial",
    )?;
    if material_value
        .get("publicMatrixSeedHash")
        .and_then(Value::as_str)
        != Some(public_matrix_seed_hash)
    {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material publicMatrixSeedHash must match publicMatrixSeedHash",
        ));
    }

    let source_trustee_identity =
        string_field(material_value, "sourceTrusteeIdentity")?.to_string();
    let source_trustee_roster_position = u64_field(material_value, "sourceTrusteeRosterPosition")?;
    let source_trustee_binding = source_trustee_bindings
        .get(&source_trustee_roster_position)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "coefficient commitment material references an unknown source trustee",
            )
        })?;
    if source_trustee_binding.source_trustee_identity != source_trustee_identity {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material source trustee identity must match the source trustee record",
        ));
    }

    let rns_limb_index = usize_field(material_value, "rnsLimbIndex")?;
    let rns_prime = u64_field(material_value, "rnsPrime")?;
    if DATA_PRIMES.get(rns_limb_index) != Some(&rns_prime) {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material rnsPrime must match Q_share at rnsLimbIndex",
        ));
    }
    let shamir_coefficient_index = u64_field(material_value, "shamirCoefficientIndex")?;
    if shamir_coefficient_index >= FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material shamirCoefficientIndex is outside the accepted threshold degree",
        ));
    }
    let commitment_root = hash_string_field(material_value, "commitmentRoot")?;
    validate_hash_string(
        commitment_root,
        "coefficientCommitmentMaterial.commitmentRoot",
    )?;
    let expected_commitment_root = source_trustee_binding
        .coefficient_commitment_roots
        .get(&(rns_limb_index, shamir_coefficient_index))
        .ok_or_else(|| {
            invalid_threshold_commitment_input(
                "coefficient commitment material coordinate is absent from the source trustee record",
            )
        })?;
    if commitment_root != expected_commitment_root {
        return Err(invalid_threshold_commitment_input(
            "coefficient commitment material root must match the source trustee coefficient commitment record",
        ));
    }

    let commitment_value = material_value.get("commitment").ok_or_else(|| {
        invalid_threshold_commitment_input(
            "coefficient commitment material must include the full public commitment",
        )
    })?;
    let commitment = parse_setup_commitment_full_value(commitment_value)?;
    if commitment.source_rns_limb_index != rns_limb_index
        || commitment.source_message_modulus != rns_prime
        || commitment.shamir_coefficient_index != shamir_coefficient_index
    {
        return Err(invalid_threshold_commitment_input(
            "full setup commitment domain must match its material wrapper",
        ));
    }
    let computed_commitment_root = setup_commitment_root(&commitment)?;
    if commitment_root != computed_commitment_root {
        return Err(invalid_threshold_commitment_input(
            "full setup commitment material does not match commitmentRoot",
        ));
    }

    Ok(CoefficientCommitmentBinding {
        source_trustee_roster_position,
        rns_limb_index,
        shamir_coefficient_index,
        commitment_root: commitment_root.to_string(),
        commitment,
    })
}

fn threshold_share_commitment_set(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    ring_degree: usize,
    ring_degree_status: &str,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    coefficient_commitments: &BTreeMap<(u64, usize, u64), CoefficientCommitmentBinding>,
) -> CanonicalResult<Value> {
    let mut recipient_records = Vec::with_capacity(FIRST_PROFILE_PARTICIPANT_COUNT);
    for recipient_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        let recipient_identity = format!("trustee-{recipient_roster_position}");
        let recipient_record = threshold_share_recipient_record(
            setup_context,
            public_matrix_seed_hash,
            &recipient_identity,
            recipient_roster_position,
            ring_degree,
            ring_degree_status,
            source_trustee_bindings,
            coefficient_commitments,
        )?;
        recipient_records.push(recipient_record);
    }

    let mut commitment_set = json!({
        "objectType": THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "participantCount": FIRST_PROFILE_PARTICIPANT_COUNT,
        "thresholdDegree": FIRST_PROFILE_DECRYPTION_THRESHOLD,
        "rnsLimbCount": DATA_PRIMES.len(),
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "recipientRecords": recipient_records,
    });
    copy_context_fields(&mut commitment_set, setup_context)?;
    let commitment_set_root =
        derive_protocol_hash("ThresholdShareCommitmentRoot", &commitment_set)?;
    commitment_set["thresholdShareCommitmentRoot"] = json!(commitment_set_root);

    Ok(commitment_set)
}

#[allow(clippy::too_many_arguments)]
fn threshold_share_recipient_record(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    ring_degree: usize,
    ring_degree_status: &str,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    coefficient_commitments: &BTreeMap<(u64, usize, u64), CoefficientCommitmentBinding>,
) -> CanonicalResult<Value> {
    let recipient_roster_position_usize =
        usize::try_from(recipient_roster_position).map_err(|_| {
            invalid_threshold_commitment_input("recipient roster position does not fit usize")
        })?;
    let mut limb_commitments = Vec::with_capacity(DATA_PRIMES.len());
    for (rns_limb_index, rns_prime) in DATA_PRIMES.iter().copied().enumerate() {
        let threshold_limb = derive_threshold_limb_commitment(
            setup_context,
            public_matrix_seed_hash,
            recipient_identity,
            recipient_roster_position,
            recipient_roster_position_usize,
            rns_limb_index,
            rns_prime,
            source_trustee_bindings,
            coefficient_commitments,
        )?;
        limb_commitments.push(threshold_limb_commitment_value(
            setup_context,
            public_matrix_seed_hash,
            recipient_identity,
            recipient_roster_position,
            recipient_roster_position_usize,
            ring_degree_status,
            &threshold_limb,
        )?);
    }
    let trustee_point = canonical_trustee_point(recipient_roster_position_usize, DATA_PRIMES[0])?;
    let mut recipient_record = json!({
        "objectType": THRESHOLD_SHARE_RECIPIENT_COMMITMENT_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "trusteePoint": trustee_point,
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "limbCommitments": limb_commitments,
    });
    copy_context_fields(&mut recipient_record, setup_context)?;
    let recipient_commitment_root =
        derive_protocol_hash("ThresholdShareCommitmentRoot", &recipient_record)?;
    recipient_record["recipientCommitmentRoot"] = json!(recipient_commitment_root);

    Ok(recipient_record)
}

#[allow(clippy::too_many_arguments)]
fn derive_threshold_limb_commitment(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    recipient_roster_position_usize: usize,
    rns_limb_index: usize,
    rns_prime: u64,
    source_trustee_bindings: &BTreeMap<u64, SourceTrusteeCommitmentBinding>,
    coefficient_commitments: &BTreeMap<(u64, usize, u64), CoefficientCommitmentBinding>,
) -> CanonicalResult<ThresholdLimbCommitment> {
    let trustee_point = canonical_trustee_point(recipient_roster_position_usize, rns_prime)?;
    let scalars = shamir_coefficient_scalars(trustee_point, FIRST_PROFILE_DECRYPTION_THRESHOLD)?;
    let mut coefficient_commitment_roots =
        Vec::with_capacity(FIRST_PROFILE_PARTICIPANT_COUNT * FIRST_PROFILE_DECRYPTION_THRESHOLD);
    let mut combination_terms =
        Vec::with_capacity(FIRST_PROFILE_PARTICIPANT_COUNT * FIRST_PROFILE_DECRYPTION_THRESHOLD);
    for source_trustee_roster_position in 0..FIRST_PROFILE_PARTICIPANT_COUNT as u64 {
        let _source_trustee_binding = source_trustee_bindings
            .get(&source_trustee_roster_position)
            .ok_or_else(|| {
                invalid_threshold_commitment_input(
                    "threshold derivation is missing an accepted source trustee binding",
                )
            })?;
        for shamir_coefficient_index in 0..FIRST_PROFILE_DECRYPTION_THRESHOLD as u64 {
            let coefficient_binding = coefficient_commitments
                .get(&(
                    source_trustee_roster_position,
                    rns_limb_index,
                    shamir_coefficient_index,
                ))
                .ok_or_else(|| {
                    invalid_threshold_commitment_input(
                        "threshold derivation is missing coefficient commitment material",
                    )
                })?;
            let scalar = scalars[shamir_coefficient_index as usize];
            coefficient_commitment_roots.push(coefficient_binding.commitment_root.clone());
            combination_terms.push((&coefficient_binding.commitment, scalar));
        }
    }

    let commitment = linear_combination_setup_commitments(&combination_terms)?;
    let threshold_limb = ThresholdLimbCommitment {
        rns_limb_index,
        rns_prime,
        threshold_share_commitment_root: String::new(),
        coefficient_commitment_roots,
        commitment,
    };
    let threshold_share_commitment_root = derive_protocol_hash(
        "ThresholdShareCommitmentRoot",
        &threshold_limb_commitment_root_payload(
            setup_context,
            public_matrix_seed_hash,
            recipient_identity,
            recipient_roster_position,
            recipient_roster_position_usize,
            &threshold_limb,
        )?,
    )?;

    Ok(ThresholdLimbCommitment {
        threshold_share_commitment_root,
        ..threshold_limb
    })
}

#[allow(clippy::too_many_arguments)]
fn threshold_limb_commitment_value(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    recipient_roster_position_usize: usize,
    ring_degree_status: &str,
    threshold_limb: &ThresholdLimbCommitment,
) -> CanonicalResult<Value> {
    let mut value = threshold_limb_commitment_root_payload(
        setup_context,
        public_matrix_seed_hash,
        recipient_identity,
        recipient_roster_position,
        recipient_roster_position_usize,
        threshold_limb,
    )?;
    value["ringDegreeStatus"] = json!(ring_degree_status);
    value["thresholdShareCommitmentRoot"] = json!(threshold_limb.threshold_share_commitment_root);

    Ok(value)
}

#[allow(clippy::too_many_arguments)]
fn threshold_limb_commitment_root_payload(
    setup_context: &Value,
    public_matrix_seed_hash: &str,
    recipient_identity: &str,
    recipient_roster_position: u64,
    recipient_roster_position_usize: usize,
    threshold_limb: &ThresholdLimbCommitment,
) -> CanonicalResult<Value> {
    let trustee_point =
        canonical_trustee_point(recipient_roster_position_usize, threshold_limb.rns_prime)?;
    let mut payload = json!({
        "objectType": THRESHOLD_SHARE_LIMB_COMMITMENT_OBJECT_TYPE,
        "objectVersion": 1,
        "setupProfileId": COLLECTIVE_BGV_SETUP_PROFILE_ID,
        "commitmentProfileId": SETUP_COMMITMENT_PROFILE_ID,
        "derivationRule": THRESHOLD_SHARE_DERIVATION_RULE,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "recipientIdentity": recipient_identity,
        "recipientRosterPosition": recipient_roster_position,
        "trusteePoint": trustee_point,
        "rnsLimbIndex": threshold_limb.rns_limb_index,
        "rnsPrime": threshold_limb.rns_prime,
        "ringDegree": threshold_limb.commitment.ring_degree,
        "ringDegreeStatus": if threshold_limb.commitment.ring_degree == POLYNOMIAL_DEGREE {
            "profile-ring"
        } else {
            "development-reduced-ring"
        },
        "shamirCoefficientScalarsDecimal": shamir_coefficient_scalars(
            trustee_point,
            FIRST_PROFILE_DECRYPTION_THRESHOLD,
        )?
        .iter()
        .map(u128::to_string)
        .collect::<Vec<_>>(),
        "coefficientCommitmentRoots": threshold_limb.coefficient_commitment_roots,
        "commitmentLimbs": commitment_limb_hash_values(&threshold_limb.commitment),
    });
    copy_context_fields(&mut payload, setup_context)?;

    Ok(payload)
}

fn commitment_limb_hash_values(commitment: &SetupCommitmentValue) -> Vec<Value> {
    commitment
        .limbs
        .iter()
        .map(|limb| {
            json!({
                "commitmentModulusIndex": limb.commitment_modulus_index,
                "modulus": limb.modulus,
                "rowCoefficientHash512": limb.rows.iter().map(|row| {
                    coefficient_vector_hash512(
                        row,
                        "sealed-lattice-threshold-share-commitment/row-coefficients-v1",
                    )
                }).collect::<Vec<_>>(),
            })
        })
        .collect()
}

fn shamir_coefficient_scalars(
    trustee_point: u64,
    coefficient_count: usize,
) -> CanonicalResult<Vec<u128>> {
    let mut scalars = Vec::with_capacity(coefficient_count);
    let mut scalar = 1_u128;
    let trustee_point_wide = u128::from(trustee_point);
    for coefficient_index in 0..coefficient_count {
        scalars.push(scalar);
        if coefficient_index + 1 < coefficient_count {
            scalar = scalar.checked_mul(trustee_point_wide).ok_or_else(|| {
                invalid_threshold_commitment_input("trustee point scalar power overflow")
            })?;
        }
    }

    Ok(scalars)
}

fn compare_context_fields(
    value: &Value,
    setup_context: &Value,
    object_path: &str,
) -> CanonicalResult<()> {
    for field_name in setup_context_field_names() {
        if value.get(field_name) != setup_context.get(field_name) {
            return Err(invalid_threshold_commitment_input(format!(
                "{object_path}.{field_name} must match setupContext"
            )));
        }
    }

    Ok(())
}

fn copy_context_fields(target: &mut Value, setup_context: &Value) -> CanonicalResult<()> {
    let target_object = target.as_object_mut().ok_or_else(|| {
        invalid_threshold_commitment_input("target context binding value must be an object")
    })?;
    for field_name in setup_context_field_names() {
        let field_value = setup_context.get(field_name).ok_or_else(|| {
            invalid_threshold_commitment_input(format!("setupContext.{field_name} is required"))
        })?;
        target_object.insert(field_name.to_string(), field_value.clone());
    }

    Ok(())
}

fn setup_context_field_names() -> [&'static str; 8] {
    [
        "ceremonyId",
        "manifestHash",
        "rosterHash",
        "setupProfileHash",
        "qShareHash",
        "carryAwareVssShareRelationProfileHash",
        "commitmentProfileHash",
        "setupEpoch",
    ]
}

fn object_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Value> {
    value
        .get(field_name)
        .filter(|field| field.is_object())
        .ok_or_else(|| {
            invalid_threshold_commitment_input(format!("{field_name} must be an object"))
        })
}

fn array_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a Vec<Value>> {
    value
        .get(field_name)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_threshold_commitment_input(format!("{field_name} must be an array")))
}

fn string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .filter(|field| !field.is_empty())
        .ok_or_else(|| {
            invalid_threshold_commitment_input(format!("{field_name} must be a non-empty string"))
        })
}

fn hash_string_field<'a>(value: &'a Value, field_name: &str) -> CanonicalResult<&'a str> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(format!(
                "{field_name} must be a protocol hash string"
            ))
        })
}

fn u64_field(value: &Value, field_name: &str) -> CanonicalResult<u64> {
    value
        .get(field_name)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            invalid_threshold_commitment_input(format!(
                "{field_name} must be a non-negative integer"
            ))
        })
}

fn usize_field(value: &Value, field_name: &str) -> CanonicalResult<usize> {
    let field_value = u64_field(value, field_name)?;
    usize::try_from(field_value)
        .map_err(|_| invalid_threshold_commitment_input(format!("{field_name} does not fit usize")))
}

fn validate_hash_string(hash: &str, field_name: &str) -> CanonicalResult<()> {
    if hash.len() == 128
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }

    Err(invalid_threshold_commitment_input(format!(
        "{field_name} must be a lowercase 512-bit hex protocol hash"
    )))
}

fn invalid_threshold_commitment_input(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
