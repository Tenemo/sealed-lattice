use std::{
    collections::{BTreeMap, btree_map::Entry},
    sync::{Arc, Mutex, OnceLock},
};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{
        CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH, CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE,
        CANONICAL_STREAM_RUNTIME_INVALID_SESSION, CanonicalStreamDomain,
        CanonicalStreamRuntimeBegin, RefusalReason, absorb_canonical_stream_chunk,
        begin_canonical_stream_verifier, cancel_canonical_stream, finish_canonical_stream_verifier,
    },
    hashing::to_hex,
};

use super::{
    evaluation_key_share_material::{
        CanonicalComponentMaterialStream, absorb_verified_canonical_component_material_chunk,
        begin_verified_canonical_component_material_stream,
        cancel_verified_canonical_component_material_stream,
        finish_verified_canonical_component_material_stream,
    },
    setup_proof::SetupProofMaterialBytes,
};

pub(crate) const BGV_CANONICAL_STREAM_FAMILY_VSS_OPENING_CARRY: u32 = 1;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_VSS_SHARE_LINKAGE: u32 = 2;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_SAME_SECRET: u32 = 3;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE: u32 = 4;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_TRUSTEE_EVALUATION_KEY: u32 = 5;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT: u32 = 6;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_GALOIS_COMPONENT: u32 = 7;

const MATERIAL_ROOT_BYTE_LENGTH: usize = 64;

#[derive(Clone)]
struct VerifiedCanonicalSetupProofMaterial {
    proof_bytes: SetupProofMaterialBytes,
    proof_family: &'static str,
}

static VERIFIED_CANONICAL_SETUP_PROOF_MATERIALS: OnceLock<
    Mutex<BTreeMap<String, VerifiedCanonicalSetupProofMaterial>>,
> = OnceLock::new();

fn verified_canonical_setup_proof_materials()
-> &'static Mutex<BTreeMap<String, VerifiedCanonicalSetupProofMaterial>> {
    VERIFIED_CANONICAL_SETUP_PROOF_MATERIALS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub(in crate::bgv::setup) fn verified_canonical_setup_proof_material_bytes(
    proof_family: &str,
    proof_material_root: &str,
) -> CanonicalResult<Option<SetupProofMaterialBytes>> {
    let materials = verified_canonical_setup_proof_materials()
        .lock()
        .map_err(|_| canonical_setup_proof_store_error())?;
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

pub(in crate::bgv::setup) fn evict_verified_canonical_setup_proof_materials(
    proof_material_roots: &[String],
) {
    let Ok(mut materials) = verified_canonical_setup_proof_materials().lock() else {
        return;
    };
    for proof_material_root in proof_material_roots {
        materials.remove(proof_material_root);
    }
}

enum BgvCanonicalStreamSink {
    SetupProof {
        bytes: Vec<u8>,
        proof_family: &'static str,
        proof_material_root: String,
    },
    EvaluationKeyComponent(CanonicalComponentMaterialStream),
}

impl BgvCanonicalStreamSink {
    fn absorb(&mut self, chunk: &[u8]) -> CanonicalResult<()> {
        match self {
            Self::SetupProof { bytes, .. } => {
                bytes.extend_from_slice(chunk);
                Ok(())
            }
            Self::EvaluationKeyComponent(stream) => {
                absorb_verified_canonical_component_material_chunk(stream, chunk)
            }
        }
    }

    fn finish(self) -> CanonicalResult<()> {
        match self {
            Self::SetupProof {
                bytes,
                proof_family,
                proof_material_root,
            } => {
                let materials = verified_canonical_setup_proof_materials();
                let mut materials = materials
                    .lock()
                    .map_err(|_| canonical_setup_proof_store_error())?;
                match materials.entry(proof_material_root) {
                    Entry::Vacant(entry) => {
                        entry.insert(VerifiedCanonicalSetupProofMaterial {
                            proof_bytes: Arc::new(bytes),
                            proof_family,
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
                finish_verified_canonical_component_material_stream(stream)
            }
        }
    }

    fn cancel(self) {
        if let Self::EvaluationKeyComponent(stream) = self {
            cancel_verified_canonical_component_material_stream(stream);
        }
    }
}

struct BgvCanonicalStreamSession {
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    handle: u32,
    sink: BgvCanonicalStreamSink,
}

#[derive(Default)]
struct BgvCanonicalStreamRegistry {
    active_session: Option<BgvCanonicalStreamSession>,
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
    if let Some(active_session) = registry.active_session.take() {
        let _ = cancel_canonical_stream(active_session.handle, &active_session.capability);
        active_session.sink.cancel();
        return Err(refusal_status(RefusalReason::OutsideSupportedProfile));
    }

    let begin = begin_canonical_stream_verifier(
        family.stream_domain.canonical_code(),
        descriptor_bytes,
        capability,
    )?;
    let material_root = to_hex(material_root);
    let sink = match family.kind {
        StreamFamilyKind::SetupProof { proof_family } => {
            if verified_canonical_setup_proof_materials()
                .lock()
                .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?
                .contains_key(&material_root)
            {
                let _ = cancel_canonical_stream(begin.handle, &capability);
                return Err(refusal_status(RefusalReason::ConsumedState));
            }
            BgvCanonicalStreamSink::SetupProof {
                bytes: Vec::new(),
                proof_family,
                proof_material_root: material_root,
            }
        }
        StreamFamilyKind::EvaluationKeyComponent => {
            let component_stream = begin_verified_canonical_component_material_stream(
                begin.handle,
                material_root,
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
    let Some(mut session) = registry.active_session.take() else {
        return absorb_canonical_stream_chunk(handle, capability, chunk_index, chunk_bytes);
    };
    let canonical_result =
        absorb_canonical_stream_chunk(handle, capability, chunk_index, chunk_bytes);
    if let Err(error) = canonical_result {
        session.sink.cancel();
        return Err(error);
    }
    if session.handle != handle || !constant_time_equal(&session.capability, capability) {
        session.sink.cancel();
        return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
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
    let Some(session) = registry.active_session.take() else {
        return finish_canonical_stream_verifier(handle, capability);
    };
    let canonical_result = finish_canonical_stream_verifier(handle, capability);
    if let Err(error) = canonical_result {
        session.sink.cancel();
        return Err(error);
    }
    if session.handle != handle || !constant_time_equal(&session.capability, capability) {
        session.sink.cancel();
        return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
    }
    session
        .sink
        .finish()
        .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)
}

pub(crate) fn cancel_bgv_canonical_stream(
    handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let active_session = registry.active_session.take();
    let canonical_result = cancel_canonical_stream(handle, capability);
    if let Some(active_session) = active_session {
        active_session.sink.cancel();
    }
    canonical_result
}

fn lock_registry() -> Result<std::sync::MutexGuard<'static, BgvCanonicalStreamRegistry>, u32> {
    match bgv_canonical_stream_registry().lock() {
        Ok(registry) => Ok(registry),
        Err(poisoned) => {
            if let Some(active_session) = poisoned.into_inner().active_session.take() {
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
    SetupProof { proof_family: &'static str },
    EvaluationKeyComponent,
}

fn stream_family(family_code: u32) -> Result<StreamFamily, u32> {
    let family = match family_code {
        BGV_CANONICAL_STREAM_FAMILY_VSS_OPENING_CARRY => StreamFamily {
            kind: StreamFamilyKind::SetupProof {
                proof_family: "vss-opening-carry",
            },
            stream_domain: CanonicalStreamDomain::DealerVssShareLinkageProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_VSS_SHARE_LINKAGE => StreamFamily {
            kind: StreamFamilyKind::SetupProof {
                proof_family: "vss-share-linkage",
            },
            stream_domain: CanonicalStreamDomain::DealerVssShareLinkageProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_SAME_SECRET => StreamFamily {
            kind: StreamFamilyKind::SetupProof {
                proof_family: "same-secret-bridge",
            },
            stream_domain: CanonicalStreamDomain::SameSecretProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE => StreamFamily {
            kind: StreamFamilyKind::SetupProof {
                proof_family: "public-key-share",
            },
            stream_domain: CanonicalStreamDomain::PublicKeyShareProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_TRUSTEE_EVALUATION_KEY => StreamFamily {
            kind: StreamFamilyKind::SetupProof {
                proof_family: "trustee-evaluation-key",
            },
            stream_domain: CanonicalStreamDomain::EvaluatorKeyAggregateProof,
        },
        BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT
        | BGV_CANONICAL_STREAM_FAMILY_GALOIS_COMPONENT => StreamFamily {
            kind: StreamFamilyKind::EvaluationKeyComponent,
            stream_domain: CanonicalStreamDomain::EvaluatorKeyStore,
        },
        _ => return Err(refusal_status(RefusalReason::MalformedEncoding)),
    };
    Ok(family)
}

fn canonical_setup_proof_store_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::ComponentMismatch,
        "canonical setup proof material store is unavailable",
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
