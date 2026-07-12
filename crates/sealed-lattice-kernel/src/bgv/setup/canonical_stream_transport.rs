use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::{Arc, Mutex, OnceLock},
};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{
        CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH, CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE,
        CANONICAL_STREAM_RUNTIME_INVALID_SESSION, CanonicalStreamDomain,
        CanonicalStreamRuntimeBegin, CanonicalStreamVerifier, FOUNDATION_PROFILE, RefusalReason,
        VerifiedCanonicalStreamSummary, absorb_canonical_stream_chunk,
        begin_canonical_stream_verifier, cancel_canonical_stream,
        derive_canonical_stream_descriptor, finish_canonical_stream_verifier_with_summary,
    },
    hashing::{derive_canonical_object_hash, to_hex},
};
use serde_json::json;

use super::{
    accepted_setup::{
        CanonicalPublicKeyShareMaterialStream,
        absorb_verified_canonical_public_key_share_material_chunk,
        begin_verified_canonical_public_key_share_material_stream,
        cancel_verified_canonical_public_key_share_material_stream,
        finish_verified_canonical_public_key_share_material_stream,
    },
    evaluation_key_share_material::{
        CanonicalComponentMaterialStream, absorb_verified_canonical_component_material_chunk,
        begin_verified_canonical_component_material_stream,
        cancel_verified_canonical_component_material_stream,
        finish_verified_canonical_component_material_stream,
    },
    setup_proof::{BgvProofMaterialBytes, CanonicalProofMaterialBytes, SetupProofMaterialBytes},
};

pub(crate) const BGV_CANONICAL_STREAM_FAMILY_VSS_OPENING_CARRY: u32 = 1;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_VSS_SHARE_LINKAGE: u32 = 2;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_SAME_SECRET: u32 = 3;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE: u32 = 4;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_TRUSTEE_EVALUATION_KEY: u32 = 5;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT: u32 = 6;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_GALOIS_COMPONENT: u32 = 7;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_TARGET_DECRYPTION_SHARE: u32 = 8;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL: u32 = 9;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_PUBLIC_EVALUATION_KEY_MATERIAL: u32 = 10;

const MATERIAL_ROOT_BYTE_LENGTH: usize = 64;

#[derive(Clone)]
struct VerifiedCanonicalProofMaterial {
    proof_bytes: BgvProofMaterialBytes,
    proof_family: &'static str,
    stream_summary: Arc<VerifiedCanonicalStreamSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::bgv::setup) struct AuthenticatedSetupTransportAccounting {
    pub(in crate::bgv::setup) total_byte_length: u64,
    pub(in crate::bgv::setup) full_object_hash: String,
    pub(in crate::bgv::setup) chunk_root: String,
    pub(in crate::bgv::setup) chunk_hashes: Vec<String>,
}

pub(in crate::bgv::setup) fn authenticated_setup_transport_accounting(
    stream_summary: &VerifiedCanonicalStreamSummary,
) -> CanonicalResult<AuthenticatedSetupTransportAccounting> {
    let chunk_hashes = stream_summary
        .ordered_chunk_digests()
        .iter()
        .map(|digest| digest.to_lowercase_hex())
        .collect::<Vec<_>>();
    let full_object_hash = stream_summary.full_object_digest().to_lowercase_hex();
    let total_byte_length = stream_summary.total_byte_length();
    let chunk_root = derive_canonical_object_hash(&json!({
        "objectType": "SetupTransportChunkManifest",
        "chunkCount": chunk_hashes.len(),
        "totalByteLength": total_byte_length,
        "chunkHashes": chunk_hashes,
        "fullObjectHash": full_object_hash,
    }))?;

    Ok(AuthenticatedSetupTransportAccounting {
        total_byte_length,
        full_object_hash,
        chunk_root,
        chunk_hashes,
    })
}

static VERIFIED_CANONICAL_PROOF_MATERIALS: OnceLock<
    Mutex<BTreeMap<String, VerifiedCanonicalProofMaterial>>,
> = OnceLock::new();

fn verified_canonical_proof_materials()
-> &'static Mutex<BTreeMap<String, VerifiedCanonicalProofMaterial>> {
    VERIFIED_CANONICAL_PROOF_MATERIALS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(in crate::bgv::setup) fn verified_canonical_setup_proof_material_bytes(
    proof_family: &str,
    proof_material_root: &str,
) -> CanonicalResult<Option<SetupProofMaterialBytes>> {
    verified_canonical_proof_material_bytes(proof_family, proof_material_root)
}

pub(crate) fn verified_canonical_proof_material_bytes(
    proof_family: &str,
    proof_material_root: &str,
) -> CanonicalResult<Option<BgvProofMaterialBytes>> {
    let materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let Some(material) = materials.get(proof_material_root) else {
        return Ok(None);
    };
    if material.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical setup proof material root belongs to a different proof family",
        ));
    }
    Ok(Some(Arc::clone(&material.proof_bytes)))
}

pub(in crate::bgv::setup) fn authenticated_setup_proof_material_stream_summary(
    proof_family: &str,
    proof_material_root: &str,
) -> CanonicalResult<Option<Arc<VerifiedCanonicalStreamSummary>>> {
    let materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let Some(material) = materials.get(proof_material_root) else {
        return Ok(None);
    };
    if material.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical setup proof material root belongs to a different proof family",
        ));
    }

    Ok(Some(Arc::clone(&material.stream_summary)))
}

pub(crate) fn take_verified_canonical_proof_material_bytes(
    proof_family: &str,
    proof_material_root: &str,
) -> CanonicalResult<Option<BgvProofMaterialBytes>> {
    let mut materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let Some(material) = materials.get(proof_material_root) else {
        return Ok(None);
    };
    if material.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical proof material root belongs to a different proof family",
        ));
    }
    Ok(materials
        .remove(proof_material_root)
        .map(|material| material.proof_bytes))
}

pub(in crate::bgv::setup) fn evict_verified_canonical_setup_proof_materials(
    proof_material_roots: &[String],
) {
    evict_verified_canonical_proof_materials(proof_material_roots);
}

pub(crate) fn evict_verified_canonical_proof_materials(proof_material_roots: &[String]) {
    let Ok(mut materials) = verified_canonical_proof_materials().lock() else {
        return;
    };
    for proof_material_root in proof_material_roots {
        materials.remove(proof_material_root);
    }
}

pub(crate) fn retain_generated_canonical_proof_material(
    proof_family: &'static str,
    proof_material_root: String,
    proof_bytes: Vec<u8>,
) -> CanonicalResult<BgvProofMaterialBytes> {
    let stream_summary = verifier_owned_generated_proof_stream_summary(proof_family, &proof_bytes)?;
    let proof_bytes = Arc::new(CanonicalProofMaterialBytes::from_contiguous(proof_bytes)?);
    let mut materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    match materials.entry(proof_material_root) {
        Entry::Vacant(entry) => {
            entry.insert(VerifiedCanonicalProofMaterial {
                proof_bytes: Arc::clone(&proof_bytes),
                proof_family,
                stream_summary,
            });
            Ok(proof_bytes)
        }
        Entry::Occupied(_) => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical generated proof material root is already retained",
        )),
    }
}

fn verifier_owned_generated_proof_stream_summary(
    proof_family: &str,
    proof_bytes: &[u8],
) -> CanonicalResult<Arc<VerifiedCanonicalStreamSummary>> {
    let stream_domain = proof_material_stream_domain(proof_family)?;
    let descriptor =
        derive_canonical_stream_descriptor(stream_domain, proof_bytes).map_err(|error| {
            canonical_stream_summary_error(format!(
                "generated proof descriptor was refused: {error:?}"
            ))
        })?;
    let mut verifier = CanonicalStreamVerifier::new(stream_domain, descriptor)
        .map_err(|_| canonical_stream_summary_error("generated proof descriptor was refused"))?;
    for (chunk_index, chunk) in proof_bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        verifier
            .absorb_chunk(chunk_index, chunk)
            .into_result()
            .map_err(|_| canonical_stream_summary_error("generated proof chunk was refused"))?;
    }
    let stream_summary = verifier.finish_with_summary().into_result().map_err(|_| {
        canonical_stream_summary_error("generated proof stream did not finish completely")
    })?;

    Ok(Arc::new(stream_summary))
}

fn proof_material_stream_domain(proof_family: &str) -> CanonicalResult<CanonicalStreamDomain> {
    match proof_family {
        "vss-opening-carry" | "vss-share-linkage" => {
            Ok(CanonicalStreamDomain::DealerVssShareLinkageProof)
        }
        "same-secret-bridge" => Ok(CanonicalStreamDomain::SameSecretProof),
        "public-key-share" => Ok(CanonicalStreamDomain::PublicKeyShareProof),
        "trustee-evaluation-key" => Ok(CanonicalStreamDomain::EvaluatorKeyAggregateProof),
        "target-decryption-share" => Ok(CanonicalStreamDomain::MaliciousTargetShareProof),
        "public-evaluation-key-material" => Ok(CanonicalStreamDomain::PublicEvaluationKeyMaterial),
        _ => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical proof material family has no stream domain",
        )),
    }
}

fn canonical_stream_summary_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

enum BgvCanonicalStreamSink {
    ProofMaterial {
        chunks: Vec<Vec<u8>>,
        proof_family: &'static str,
        proof_material_root: String,
    },
    EvaluationKeyComponent(CanonicalComponentMaterialStream),
    PublicKeyShareMaterial(CanonicalPublicKeyShareMaterialStream),
}

impl BgvCanonicalStreamSink {
    fn absorb(&mut self, chunk: &[u8]) -> CanonicalResult<()> {
        match self {
            Self::ProofMaterial { chunks, .. } => {
                chunks.push(chunk.to_vec());
                Ok(())
            }
            Self::EvaluationKeyComponent(stream) => {
                absorb_verified_canonical_component_material_chunk(stream, chunk)
            }
            Self::PublicKeyShareMaterial(stream) => {
                absorb_verified_canonical_public_key_share_material_chunk(stream, chunk)
            }
        }
    }

    fn finish(self, stream_summary: Arc<VerifiedCanonicalStreamSummary>) -> CanonicalResult<()> {
        match self {
            Self::ProofMaterial {
                chunks,
                proof_family,
                proof_material_root,
            } => {
                let proof_bytes =
                    Arc::new(CanonicalProofMaterialBytes::from_stream_chunks(chunks)?);
                if stream_summary.stream_domain() != proof_material_stream_domain(proof_family)?
                    || stream_summary.total_byte_length()
                        != u64::try_from(proof_bytes.len()).map_err(|_| {
                            CanonicalError::new(
                                CanonicalErrorCode::MalformedLength,
                                "canonical proof material byte length does not fit u64",
                            )
                        })?
                {
                    return Err(CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "canonical proof material does not match its authenticated stream summary",
                    ));
                }
                let materials = verified_canonical_proof_materials();
                let mut materials = materials
                    .lock()
                    .map_err(|_| canonical_proof_store_error())?;
                match materials.entry(proof_material_root) {
                    Entry::Vacant(entry) => {
                        entry.insert(VerifiedCanonicalProofMaterial {
                            proof_bytes,
                            proof_family,
                            stream_summary,
                        });
                        Ok(())
                    }
                    Entry::Occupied(_) => Err(CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "canonical setup proof material root was already consumed",
                    )),
                }
            }
            Self::EvaluationKeyComponent(stream) => {
                finish_verified_canonical_component_material_stream(stream, stream_summary)
            }
            Self::PublicKeyShareMaterial(stream) => {
                finish_verified_canonical_public_key_share_material_stream(stream, stream_summary)
            }
        }
    }

    fn cancel(self) {
        match self {
            Self::EvaluationKeyComponent(stream) => {
                cancel_verified_canonical_component_material_stream(stream);
            }
            Self::PublicKeyShareMaterial(stream) => {
                cancel_verified_canonical_public_key_share_material_stream(stream);
            }
            Self::ProofMaterial { .. } => {}
        }
    }
}

struct BgvCanonicalStreamSession {
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    handle: u32,
    sink: BgvCanonicalStreamSink,
}

struct BgvCanonicalMaterialReaderSession {
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    handle: u32,
    material: BgvProofMaterialBytes,
    material_root: String,
    next_chunk_index: usize,
    proof_family: &'static str,
}

struct BgvCanonicalStreamRegistry {
    active_session: Option<BgvCanonicalStreamSession>,
    active_material_reader: Option<BgvCanonicalMaterialReaderSession>,
    next_material_reader_handle: Option<u32>,
}

impl Default for BgvCanonicalStreamRegistry {
    fn default() -> Self {
        Self {
            active_session: None,
            active_material_reader: None,
            next_material_reader_handle: Some(1),
        }
    }
}

impl BgvCanonicalStreamRegistry {
    fn refuse_overlapping_transaction(&self) -> Result<(), u32> {
        if self.active_session.is_some() || self.active_material_reader.is_some() {
            Err(refusal_status(RefusalReason::OutsideSupportedProfile))
        } else {
            Ok(())
        }
    }

    fn take_owned_stream_session(
        &mut self,
        handle: u32,
        capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    ) -> Result<BgvCanonicalStreamSession, u32> {
        let Some(active_session) = self.active_session.as_ref() else {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        };
        if active_session.handle != handle
            || !constant_time_equal(&active_session.capability, capability)
        {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        }
        Ok(self
            .active_session
            .take()
            .expect("authenticated BGV canonical stream session remains active"))
    }

    fn take_owned_material_reader(
        &mut self,
        handle: u32,
        capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    ) -> Result<BgvCanonicalMaterialReaderSession, u32> {
        let Some(reader) = self.active_material_reader.as_ref() else {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        };
        if reader.handle != handle || !constant_time_equal(&reader.capability, capability) {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        }
        Ok(self
            .active_material_reader
            .take()
            .expect("authenticated BGV material-reader session remains active"))
    }

    fn take_material_reader_handle(&mut self) -> Result<u32, u32> {
        let handle = self
            .next_material_reader_handle
            .ok_or(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
        self.next_material_reader_handle = handle.checked_add(1);
        Ok(handle)
    }
}

static BGV_CANONICAL_STREAM_REGISTRY: OnceLock<Mutex<BgvCanonicalStreamRegistry>> = OnceLock::new();

fn bgv_canonical_stream_registry() -> &'static Mutex<BgvCanonicalStreamRegistry> {
    BGV_CANONICAL_STREAM_REGISTRY.get_or_init(|| Mutex::new(BgvCanonicalStreamRegistry::default()))
}

pub(crate) fn begin_bgv_canonical_stream(
    family_code: u32,
    material_root: &[u8],
    descriptor_bytes: &[u8],
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Result<CanonicalStreamRuntimeBegin, u32> {
    if material_root.len() != MATERIAL_ROOT_BYTE_LENGTH {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let family = stream_family(family_code)?;
    let mut registry = lock_registry()?;
    registry.refuse_overlapping_transaction()?;

    let begin = begin_canonical_stream_verifier(
        family.stream_domain.canonical_code(),
        descriptor_bytes,
        capability,
    )?;
    let material_root = to_hex(material_root);
    let sink = match family.kind {
        StreamFamilyKind::ProofMaterial { proof_family } => {
            if verified_canonical_proof_materials()
                .lock()
                .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?
                .contains_key(&material_root)
            {
                let _ = cancel_canonical_stream(begin.handle, &capability);
                return Err(refusal_status(RefusalReason::ConsumedState));
            }
            BgvCanonicalStreamSink::ProofMaterial {
                chunks: Vec::new(),
                proof_family,
                proof_material_root: material_root,
            }
        }
        StreamFamilyKind::EvaluationKeyComponent { proof_family } => {
            let component_stream = begin_verified_canonical_component_material_stream(
                begin.handle,
                material_root,
                proof_family,
                u64::from(begin.total_byte_length),
            )
            .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
            match component_stream {
                Ok(component_stream) => {
                    BgvCanonicalStreamSink::EvaluationKeyComponent(component_stream)
                }
                Err(error) => {
                    let _ = cancel_canonical_stream(begin.handle, &capability);
                    return Err(error);
                }
            }
        }
        StreamFamilyKind::PublicKeyShareMaterial => {
            let material_stream = begin_verified_canonical_public_key_share_material_stream(
                material_root,
                u64::from(begin.total_byte_length),
            )
            .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
            match material_stream {
                Ok(material_stream) => {
                    BgvCanonicalStreamSink::PublicKeyShareMaterial(material_stream)
                }
                Err(error) => {
                    let _ = cancel_canonical_stream(begin.handle, &capability);
                    return Err(error);
                }
            }
        }
    };
    registry.active_session = Some(BgvCanonicalStreamSession {
        capability,
        handle: begin.handle,
        sink,
    });
    Ok(begin)
}

pub(crate) fn absorb_bgv_canonical_stream_chunk(
    handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    chunk_index: u32,
    chunk_bytes: &[u8],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let mut session = registry.take_owned_stream_session(handle, capability)?;
    let canonical_result =
        absorb_canonical_stream_chunk(handle, capability, chunk_index, chunk_bytes);
    if let Err(error) = canonical_result {
        session.sink.cancel();
        return Err(error);
    }
    if session.sink.absorb(chunk_bytes).is_err() {
        let _ = cancel_canonical_stream(handle, capability);
        session.sink.cancel();
        return Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
    }
    registry.active_session = Some(session);
    Ok(())
}

pub(crate) fn finish_bgv_canonical_stream(
    handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let session = registry.take_owned_stream_session(handle, capability)?;
    let stream_summary = match finish_canonical_stream_verifier_with_summary(handle, capability) {
        Ok(stream_summary) => Arc::new(stream_summary),
        Err(error) => {
            session.sink.cancel();
            return Err(error);
        }
    };
    session
        .sink
        .finish(stream_summary)
        .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)
}

pub(crate) fn cancel_bgv_canonical_stream(
    handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let active_session = registry.take_owned_stream_session(handle, capability)?;
    let canonical_result = cancel_canonical_stream(handle, capability);
    active_session.sink.cancel();
    canonical_result
}

pub(crate) fn begin_bgv_canonical_material_reader(
    family_code: u32,
    material_root: &[u8],
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Result<CanonicalStreamRuntimeBegin, u32> {
    if material_root.len() != MATERIAL_ROOT_BYTE_LENGTH {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    if capability.iter().all(|byte| *byte == 0) {
        return Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
    }
    let family = stream_family(family_code)?;
    let StreamFamilyKind::ProofMaterial { proof_family } = family.kind else {
        return Err(refusal_status(RefusalReason::MalformedEncoding));
    };
    let material_root = to_hex(material_root);
    let material = verified_canonical_proof_material_bytes(proof_family, &material_root)
        .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?
        .ok_or_else(|| refusal_status(RefusalReason::ConsumedState))?;
    let total_byte_length = u32::try_from(material.len())
        .map_err(|_| refusal_status(RefusalReason::OutsideSupportedProfile))?;
    let chunk_count = u32::try_from(material.chunk_count())
        .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;

    let mut registry = lock_registry()?;
    registry.refuse_overlapping_transaction()?;
    let handle = registry.take_material_reader_handle()?;
    registry.active_material_reader = Some(BgvCanonicalMaterialReaderSession {
        capability,
        handle,
        material,
        material_root,
        next_chunk_index: 0,
        proof_family,
    });

    Ok(CanonicalStreamRuntimeBegin {
        handle,
        total_byte_length,
        chunk_count,
    })
}

pub(crate) fn read_bgv_canonical_material_chunk(
    handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    chunk_index: u32,
    output: &mut [u8],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let mut reader = registry.take_owned_material_reader(handle, capability)?;
    let chunk_index = usize::try_from(chunk_index)
        .map_err(|_| refusal_status(RefusalReason::WrongTypeOrLength))?;
    if chunk_index != reader.next_chunk_index {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let chunk = reader
        .material
        .chunk(chunk_index)
        .ok_or_else(|| refusal_status(RefusalReason::WrongTypeOrLength))?;
    if output.len() != chunk.len() {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    output.copy_from_slice(chunk);
    reader.next_chunk_index += 1;
    registry.active_material_reader = Some(reader);

    Ok(())
}

pub(crate) fn finish_bgv_canonical_material_reader(
    handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let reader = registry.take_owned_material_reader(handle, capability)?;
    let material_was_complete = reader.next_chunk_index == reader.material.chunk_count();
    evict_material_reader_source(&reader)?;
    if !material_was_complete {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }

    Ok(())
}

pub(crate) fn cancel_bgv_canonical_material_reader(
    handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let reader = registry.take_owned_material_reader(handle, capability)?;
    evict_material_reader_source(&reader)?;

    Ok(())
}

fn evict_material_reader_source(reader: &BgvCanonicalMaterialReaderSession) -> Result<(), u32> {
    let mut materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
    if let Some(material) = materials.get(&reader.material_root)
        && material.proof_family != reader.proof_family
    {
        return Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
    }
    materials.remove(&reader.material_root);
    Ok(())
}

fn lock_registry() -> Result<std::sync::MutexGuard<'static, BgvCanonicalStreamRegistry>, u32> {
    match bgv_canonical_stream_registry().lock() {
        Ok(registry) => Ok(registry),
        Err(poisoned) => {
            let mut registry = poisoned.into_inner();
            registry.active_material_reader = None;
            if let Some(active_session) = registry.active_session.take() {
                let _ = cancel_canonical_stream(active_session.handle, &active_session.capability);
                active_session.sink.cancel();
            }
            Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)
        }
    }
}

struct StreamFamily {
    kind: StreamFamilyKind,
    stream_domain: CanonicalStreamDomain,
}

enum StreamFamilyKind {
    ProofMaterial { proof_family: &'static str },
    EvaluationKeyComponent { proof_family: &'static str },
    PublicKeyShareMaterial,
}

fn stream_family(family_code: u32) -> Result<StreamFamily, u32> {
    let family = match family_code {
        BGV_CANONICAL_STREAM_FAMILY_VSS_OPENING_CARRY => StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: "vss-opening-carry",
            },
            stream_domain: CanonicalStreamDomain::DealerVssShareLinkageProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_VSS_SHARE_LINKAGE => StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: "vss-share-linkage",
            },
            stream_domain: CanonicalStreamDomain::DealerVssShareLinkageProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_SAME_SECRET => StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: "same-secret-bridge",
            },
            stream_domain: CanonicalStreamDomain::SameSecretProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE => StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: "public-key-share",
            },
            stream_domain: CanonicalStreamDomain::PublicKeyShareProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_TRUSTEE_EVALUATION_KEY => StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: "trustee-evaluation-key",
            },
            stream_domain: CanonicalStreamDomain::EvaluatorKeyAggregateProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT => StreamFamily {
            kind: StreamFamilyKind::EvaluationKeyComponent {
                proof_family: "relinearization-key-share",
            },
            stream_domain: CanonicalStreamDomain::EvaluatorKeyStore,
        },
        BGV_CANONICAL_STREAM_FAMILY_GALOIS_COMPONENT => StreamFamily {
            kind: StreamFamilyKind::EvaluationKeyComponent {
                proof_family: "galois-key-share",
            },
            stream_domain: CanonicalStreamDomain::EvaluatorKeyStore,
        },
        BGV_CANONICAL_STREAM_FAMILY_TARGET_DECRYPTION_SHARE => StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: "target-decryption-share",
            },
            stream_domain: CanonicalStreamDomain::MaliciousTargetShareProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL => StreamFamily {
            kind: StreamFamilyKind::PublicKeyShareMaterial,
            stream_domain: CanonicalStreamDomain::PublicKeyShareMaterial,
        },
        BGV_CANONICAL_STREAM_FAMILY_PUBLIC_EVALUATION_KEY_MATERIAL => StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: "public-evaluation-key-material",
            },
            stream_domain: CanonicalStreamDomain::PublicEvaluationKeyMaterial,
        },
        _ => return Err(refusal_status(RefusalReason::MalformedEncoding)),
    };
    Ok(family)
}

fn canonical_proof_store_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::ComponentMismatch,
        "canonical proof material store is unavailable",
    )
}

fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    u32::from(refusal_reason.canonical_code())
}

fn constant_time_equal(
    left: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    right: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> bool {
    let mut difference = 0_u8;
    for byte_index in 0..CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH {
        difference |= left[byte_index] ^ right[byte_index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_material() -> BgvProofMaterialBytes {
        Arc::new(
            CanonicalProofMaterialBytes::from_contiguous(vec![0x5a; 17])
                .expect("test proof material is non-empty"),
        )
    }

    #[test]
    fn wrong_owner_cannot_consume_bgv_stream_or_material_reader_sessions() {
        let stream_capability = [0x11; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let reader_capability = [0x22; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let mut registry = BgvCanonicalStreamRegistry {
            active_session: Some(BgvCanonicalStreamSession {
                capability: stream_capability,
                handle: 41,
                sink: BgvCanonicalStreamSink::ProofMaterial {
                    chunks: Vec::new(),
                    proof_family: "public-key-share",
                    proof_material_root: "00".repeat(MATERIAL_ROOT_BYTE_LENGTH),
                },
            }),
            active_material_reader: Some(BgvCanonicalMaterialReaderSession {
                capability: reader_capability,
                handle: 57,
                material: retained_material(),
                material_root: "11".repeat(MATERIAL_ROOT_BYTE_LENGTH),
                next_chunk_index: 0,
                proof_family: "public-key-share",
            }),
            next_material_reader_handle: Some(1),
        };

        assert!(matches!(
            registry.take_owned_stream_session(42, &stream_capability),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
        ));
        assert!(registry.active_session.is_some());
        assert!(matches!(
            registry
                .take_owned_stream_session(41, &[0x33; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
        ));
        assert!(registry.active_session.is_some());
        assert!(matches!(
            registry.take_owned_material_reader(58, &reader_capability),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
        ));
        assert!(registry.active_material_reader.is_some());
        assert!(matches!(
            registry
                .take_owned_material_reader(57, &[0x44; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
        ));
        assert!(registry.active_material_reader.is_some());
    }

    #[test]
    fn refused_overlap_preserves_the_active_bgv_transaction() {
        let registry = BgvCanonicalStreamRegistry {
            active_material_reader: Some(BgvCanonicalMaterialReaderSession {
                capability: [0x51; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
                handle: 3,
                material: retained_material(),
                material_root: "22".repeat(MATERIAL_ROOT_BYTE_LENGTH),
                next_chunk_index: 0,
                proof_family: "public-key-share",
            }),
            ..BgvCanonicalStreamRegistry::default()
        };

        assert_eq!(
            registry.refuse_overlapping_transaction(),
            Err(refusal_status(RefusalReason::OutsideSupportedProfile)),
        );
        assert!(registry.active_material_reader.is_some());
    }

    #[test]
    fn material_reader_handle_exhaustion_fails_closed_without_reuse() {
        let mut registry = BgvCanonicalStreamRegistry {
            next_material_reader_handle: Some(u32::MAX),
            ..BgvCanonicalStreamRegistry::default()
        };

        assert_eq!(registry.take_material_reader_handle(), Ok(u32::MAX),);
        assert_eq!(registry.next_material_reader_handle, None);
        assert_eq!(
            registry.take_material_reader_handle(),
            Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE),
        );
    }

    #[test]
    fn material_reader_finish_and_cancel_evict_retained_source_material() {
        let finished_root = "a1".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        let cancelled_root = "a2".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        evict_verified_canonical_proof_materials(&[finished_root.clone(), cancelled_root.clone()]);

        let finished_material = retain_generated_canonical_proof_material(
            "public-key-share",
            finished_root.clone(),
            vec![0x61; 17],
        )
        .expect("finished material fixture");
        let finished_capability = [0x61; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        {
            let mut registry = lock_registry().expect("BGV stream registry");
            assert!(registry.active_material_reader.is_none());
            registry.active_material_reader = Some(BgvCanonicalMaterialReaderSession {
                capability: finished_capability,
                handle: 61,
                material: Arc::clone(&finished_material),
                material_root: finished_root.clone(),
                next_chunk_index: finished_material.chunk_count(),
                proof_family: "public-key-share",
            });
        }
        finish_bgv_canonical_material_reader(61, &finished_capability)
            .expect("complete material reader finish");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &finished_root)
                .expect("finished material store lookup")
                .is_none()
        );

        let cancelled_material = retain_generated_canonical_proof_material(
            "public-key-share",
            cancelled_root.clone(),
            vec![0x62; 17],
        )
        .expect("cancelled material fixture");
        let cancelled_capability = [0x62; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        {
            let mut registry = lock_registry().expect("BGV stream registry");
            assert!(registry.active_material_reader.is_none());
            registry.active_material_reader = Some(BgvCanonicalMaterialReaderSession {
                capability: cancelled_capability,
                handle: 62,
                material: cancelled_material,
                material_root: cancelled_root.clone(),
                next_chunk_index: 0,
                proof_family: "public-key-share",
            });
        }
        cancel_bgv_canonical_material_reader(62, &cancelled_capability)
            .expect("incomplete material reader cancellation");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &cancelled_root)
                .expect("cancelled material store lookup")
                .is_none()
        );
    }
}
