use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, OnceLock},
};

use serde_json::{Value, json};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    bgv::{
        coefficient_codec::coefficient_vector_hash512,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult, append_bytes, append_varuint},
    hashing::{HASH512_PREIMAGE_PREFIX, hash512_hex, to_hex},
    transcript_core::decode_hex,
};

use super::{
    accepted_setup::{
        AcceptedRosterParameters, accepted_roster_from_setup_context,
        setup_parameters_hash_for_roster,
    },
    commitment::{
        SETUP_COMMITMENT_MODULUS_LIMB_INDICES, SETUP_COMMITMENT_ROW_COUNT, SetupCommitmentLimb,
        SetupCommitmentValue, add_scaled_setup_commitment_in_place,
        linear_combination_setup_commitments, parse_setup_commitment_full_value,
        setup_commitment_root,
    },
    sharing::canonical_trustee_point,
};

const VSS_SOURCE_TRUSTEE_COMMITMENT_OBJECT_TYPE: &str = "VssSourceTrusteeCoefficientCommitments";
const VSS_COEFFICIENT_COMMITMENT_OBJECT_TYPE: &str = "VssCoefficientCommitment";
const VSS_COEFFICIENT_COMMITMENT_MATERIAL_OBJECT_TYPE: &str = "VssCoefficientCommitmentMaterial";
const THRESHOLD_SHARE_COMMITMENT_SET_OBJECT_TYPE: &str = "ThresholdShareCommitmentSet";
const THRESHOLD_SHARE_RECIPIENT_COMMITMENT_OBJECT_TYPE: &str = "TrusteeThresholdShareCommitments";
const THRESHOLD_SHARE_LIMB_COMMITMENT_OBJECT_TYPE: &str = "ThresholdShareCommitment";
const THRESHOLD_SHARE_DERIVATION_RULE: &str =
    "sum-source-trustee-polynomial-commitments-at-trustee-point";
const SETUP_TRANSPORT_SCHEME_ID: &str = "sealed-lattice-setup-binary-chunked-transport-v1";
const SETUP_TRANSPORT_CHUNK_MANIFEST_OBJECT_TYPE: &str = "SetupTransportChunkManifest";
const SETUP_TRANSPORT_CHUNK_SIZE_BYTES: u64 = 1_048_576;
const VSS_MATERIAL_BINARY_OBJECT_TYPE: &str = "SetupTransportedVssCoefficientCommitmentMaterial";
const VERIFIED_VSS_MATERIAL_OBJECT_TYPE: &str = "VerifiedVssCoefficientCommitmentMaterial";
const VSS_MATERIAL_BINARY_FORMAT: &str =
    "sealed-lattice-vss-coefficient-commitment-material-binary-v1";
const VSS_MATERIAL_BINARY_MAGIC: &[u8] = b"SLVSSMAT";
const VSS_MATERIAL_BINARY_VERSION: u64 = 1;
const VSS_TRANSPORT_STREAM_DERIVATION_ID_MAX_BYTES: usize = 128;
const VSS_TRANSPORT_MAX_ACTIVE_DERIVATION_SESSIONS: usize = 64;
const VSS_TRANSPORT_MAX_VERIFIED_MATERIALS: usize = 128;

// Threshold-share-commitment derivation is split by responsibility. This module
// owns the request entry points, the module-level constants (which the
// sub-modules reach through `use super::*;`), and the orchestration of the
// in-parts and transport derivations. The sibling modules own input
// verification, the canonical commitment-set serialization, the binary transport
// codec, and the stateful streaming session store.
mod binary_transport;
mod coefficient_verification;
mod support;
mod threshold_derivation;
mod transport_streaming;

use binary_transport::*;
use coefficient_verification::*;
use support::*;
use threshold_derivation::*;
use transport_streaming::*;

pub(crate) use binary_transport::{
    SetupVssMaterialTransportHashes, setup_vss_material_transport_hashes,
};
pub(crate) use transport_streaming::{
    VerifiedTransportedConstantVssCommitments, VerifiedTransportedVssMaterial,
    with_verified_transported_vss_material,
};

pub(crate) fn derive_threshold_share_commitments_from_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let setup_context = object_field(request, "setupContext")?;
    let public_matrix_seed_hash = hash_string_field(request, "publicMatrixSeedHash")?;
    let source_trustee_record_values =
        array_field(request, "sourceTrusteeCoefficientCommitmentRecords")?;
    let commitment_material_values = array_field(request, "coefficientCommitments")?;
    let roster = accepted_roster_from_setup_context(setup_context);

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
        "operation": "deriveThresholdShareCommitments",
        "ringDegree": ring_degree,
        "ringDegreeStatus": ring_degree_status,
        "participantCount": roster.participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": roster.decryption_threshold,
        "derivedLimbCommitmentCount": roster.participant_count as usize * DATA_PRIMES.len(),
        "thresholdShareCommitmentRoot": threshold_share_commitment_root,
        "thresholdShareCommitments": threshold_share_commitments,
    }))
}

pub(crate) fn derive_threshold_share_commitments_from_transport_request(
    request: &Value,
) -> CanonicalResult<Value> {
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
    let roster = accepted_roster_from_setup_context(setup_context);
    let source_trustee_bindings = verify_source_trustee_commitment_records(
        source_trustee_record_values,
        setup_context,
        public_matrix_seed_hash,
        &roster,
    )?;
    let transport = read_transport_material(transported_material)?;
    let hashes =
        setup_vss_material_transport_hashes(&transport.chunks, SETUP_TRANSPORT_CHUNK_SIZE_BYTES)?;
    compare_transport_hashes(&transport, &hashes)?;

    let derivation = derive_threshold_share_commitment_set_from_transport_bytes(
        setup_context,
        public_matrix_seed_hash,
        &roster,
        &source_trustee_bindings,
        &transport.chunks,
    )?;
    let material_record_count = roster.participant_count as usize
        * DATA_PRIMES.len()
        * roster.decryption_threshold as usize;
    let material_set = transported_vss_material_set_value(
        setup_context,
        public_matrix_seed_hash,
        derivation.ring_degree,
        derivation.ring_degree_status,
        &roster,
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
        "operation": "deriveThresholdShareCommitmentsFromTransport",
        "materialBinaryFormat": VSS_MATERIAL_BINARY_FORMAT,
        "ringDegree": derivation.ring_degree,
        "ringDegreeStatus": derivation.ring_degree_status,
        "participantCount": roster.participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": roster.decryption_threshold,
        "derivedLimbCommitmentCount": roster.participant_count as usize * DATA_PRIMES.len(),
        "transport": {
            "transportSchemeId": SETUP_TRANSPORT_SCHEME_ID,
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

pub(crate) fn begin_threshold_share_commitment_transport_derivation_stream_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let derivation_id = derivation_stream_id_field(request, "derivationId")?.to_string();
    let setup_context = object_field(request, "setupContext")?;
    let public_matrix_seed_hash = hash_string_field(request, "publicMatrixSeedHash")?;
    let transported_material =
        object_field(request, "transportedVssCoefficientCommitmentMaterial")?;

    verify_setup_context(setup_context)?;
    validate_hash_string(public_matrix_seed_hash, "publicMatrixSeedHash")?;
    let roster = accepted_roster_from_setup_context(setup_context);
    let transport_header = read_transport_material_stream_header(transported_material)?;
    let sessions = vss_transport_derivation_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        invalid_threshold_commitment_input("transport derivation session store is unavailable")
    })?;
    if sessions.contains_key(&derivation_id) {
        return Err(invalid_threshold_commitment_input(
            "transport derivationId is already active",
        ));
    }
    if sessions.len() >= VSS_TRANSPORT_MAX_ACTIVE_DERIVATION_SESSIONS {
        return Err(invalid_threshold_commitment_input(
            "transport derivation session store is full; finish or abort an active stream before beginning another",
        ));
    }
    if vss_transport_verified_materials()
        .lock()
        .map_err(|_| invalid_threshold_commitment_input("verified material store is unavailable"))?
        .contains_key(&derivation_id)
    {
        return Err(invalid_threshold_commitment_input(
            "transport derivationId already has verified material",
        ));
    }
    let full_object_hasher = streaming_hash512_hasher(
        "sealed-lattice/setup/vss-coefficient-commitment-material/full-object-v1",
        transport_header.total_byte_length,
    );
    let observed_chunk_hashes = Vec::with_capacity(transport_header.chunk_count);
    sessions.insert(
        derivation_id.clone(),
        VssTransportThresholdDerivationSession {
            setup_context: setup_context.clone(),
            public_matrix_seed_hash: public_matrix_seed_hash.to_string(),
            transport_header: transport_header.clone(),
            observed_chunk_hashes,
            full_object_hasher,
            next_chunk_index: 0,
            observed_total_byte_length: 0,
            parser: StreamingVssThresholdMaterialParser::new(roster),
        },
    );

    Ok(json!({
        "operation": "beginThresholdShareCommitmentsFromTransportStream",
        "derivationId": derivation_id,
        "materialBinaryFormat": VSS_MATERIAL_BINARY_FORMAT,
        "transport": {
            "transportSchemeId": SETUP_TRANSPORT_SCHEME_ID,
            "chunkSizeBytes": SETUP_TRANSPORT_CHUNK_SIZE_BYTES,
            "chunkCount": transport_header.chunk_count,
            "totalByteLength": transport_header.total_byte_length,
        },
    }))
}

pub(crate) fn absorb_threshold_share_commitment_transport_derivation_stream_chunk_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let derivation_id = derivation_stream_id_field(request, "derivationId")?.to_string();
    let chunk_index = usize_field(request, "chunkIndex")?;
    let bytes_hex = string_field(request, "bytesHex")?;
    let chunk = decode_hex(bytes_hex)?;
    let sessions = vss_transport_derivation_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        invalid_threshold_commitment_input("transport derivation session store is unavailable")
    })?;
    let absorb_result = {
        let session = sessions.get_mut(&derivation_id).ok_or_else(|| {
            invalid_threshold_commitment_input("transport derivationId is not active")
        })?;
        absorb_threshold_share_commitment_transport_chunk(session, chunk_index, &chunk)
    };
    match absorb_result {
        Ok(response) => Ok(response),
        Err(error) => {
            sessions.remove(&derivation_id);
            Err(error)
        }
    }
}

pub(crate) fn finish_threshold_share_commitment_transport_derivation_stream_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let derivation_id = derivation_stream_id_field(request, "derivationId")?.to_string();
    let vss_coefficient_commitment_root =
        hash_string_field(request, "vssCoefficientCommitmentRoot")?.to_string();
    let source_trustee_record_values =
        array_field(request, "sourceTrusteeCoefficientCommitmentRecords")?.clone();
    let sessions = vss_transport_derivation_sessions();
    let mut sessions = sessions.lock().map_err(|_| {
        invalid_threshold_commitment_input("transport derivation session store is unavailable")
    })?;
    let session = sessions.remove(&derivation_id).ok_or_else(|| {
        invalid_threshold_commitment_input("transport derivationId is not active")
    })?;
    drop(sessions);

    finish_threshold_share_commitment_transport_stream(
        &derivation_id,
        session,
        &vss_coefficient_commitment_root,
        &source_trustee_record_values,
    )
}

pub(crate) fn release_verified_transported_vss_material_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let verification_id = derivation_stream_id_field(request, "verificationId")?.to_string();
    let verified_materials = vss_transport_verified_materials();
    let mut verified_materials = verified_materials.lock().map_err(|_| {
        invalid_threshold_commitment_input("verified material store is unavailable")
    })?;
    verified_materials.remove(&verification_id);

    Ok(json!({
        "operation": "releaseVerifiedTransportedVssMaterial",
        "verificationId": verification_id,
    }))
}

pub(crate) fn verify_constant_vss_commitments_from_transport_request(
    request: &Value,
) -> CanonicalResult<VerifiedTransportedConstantVssCommitments> {
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
    let roster = accepted_roster_from_setup_context(setup_context);
    let source_trustee_bindings = verify_source_trustee_commitment_records(
        source_trustee_record_values,
        setup_context,
        public_matrix_seed_hash,
        &roster,
    )?;
    let transport = read_transport_material(transported_material)?;
    let hashes =
        setup_vss_material_transport_hashes(&transport.chunks, SETUP_TRANSPORT_CHUNK_SIZE_BYTES)?;
    compare_transport_hashes(&transport, &hashes)?;

    let constant_material = read_constant_vss_commitments_from_transport_bytes(
        &roster,
        &source_trustee_bindings,
        &transport.chunks,
    )?;
    let material_record_count = roster.participant_count as usize
        * DATA_PRIMES.len()
        * roster.decryption_threshold as usize;
    let material_set = transported_vss_material_set_value(
        setup_context,
        public_matrix_seed_hash,
        constant_material.ring_degree,
        constant_material.ring_degree_status,
        &roster,
        material_record_count,
        vss_coefficient_commitment_root,
        &hashes,
    )?;

    Ok(VerifiedTransportedConstantVssCommitments {
        material_set,
        constant_commitments_by_source_trustee: Arc::new(
            constant_material.constant_commitments_by_source_trustee,
        ),
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
    let roster = accepted_roster_from_setup_context(setup_context);
    let source_trustee_bindings = verify_source_trustee_commitment_records(
        source_trustee_record_values,
        setup_context,
        public_matrix_seed_hash,
        &roster,
    )?;
    let coefficient_commitments = verify_coefficient_commitment_material(
        commitment_material_values,
        setup_context,
        public_matrix_seed_hash,
        &roster,
        &source_trustee_bindings,
    )?;

    let ring_degree = coefficient_commitments
        .values()
        .next()
        .map(|binding| binding.commitment.ring_degree)
        .ok_or_else(|| invalid_threshold_commitment_input("no coefficient commitments supplied"))?;
    let ring_degree_status = if ring_degree == POLYNOMIAL_DEGREE {
        "full-ring"
    } else {
        "development-reduced-ring"
    };

    let threshold_share_commitments = threshold_share_commitment_set(
        setup_context,
        public_matrix_seed_hash,
        ring_degree,
        ring_degree_status,
        &roster,
        &source_trustee_bindings,
        &coefficient_commitments,
    )?;

    Ok(threshold_share_commitments)
}
