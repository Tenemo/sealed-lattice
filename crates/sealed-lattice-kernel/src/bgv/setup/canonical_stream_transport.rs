use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    sync::{Arc, Mutex, OnceLock},
};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{
        CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE, CANONICAL_STREAM_RUNTIME_INVALID_SESSION,
        CanonicalStreamDomain, CanonicalStreamRuntimeBegin, CanonicalStreamVerifier,
        FOUNDATION_PROFILE, RefusalReason, VerifiedCanonicalStreamSummary,
        absorb_canonical_stream_chunk, begin_canonical_stream_verifier, cancel_canonical_stream,
        derive_canonical_stream_descriptor, finish_canonical_stream_verifier_with_summary,
    },
    hashing::to_hex,
};

use super::{
    accepted_setup::{
        CanonicalPublicKeyShareMaterialStream, VerifiedCanonicalPublicKeyShareMaterialStoreEntry,
        absorb_verified_canonical_public_key_share_material_chunk,
        begin_verified_canonical_public_key_share_material_stream,
        cancel_verified_canonical_public_key_share_material_stream,
        finish_verified_canonical_public_key_share_material_stream,
    },
    evaluation_key_share_material::{
        CanonicalComponentMaterialStream,
        VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry,
        absorb_verified_canonical_component_material_chunk,
        begin_verified_canonical_component_material_stream,
        cancel_verified_canonical_component_material_stream,
        finish_verified_canonical_component_material_stream,
    },
    setup_proof::{
        BgvProofMaterialBytes, CanonicalProofMaterialBytes, SetupProofFamily,
        SetupProofMaterialBytes,
    },
};

#[cfg(test)]
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE: u32 =
    SetupProofFamily::PublicKeyShare.stream_code();
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT: u32 = 6;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_GALOIS_COMPONENT: u32 = 7;
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL: u32 = 9;
#[cfg(test)]
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_TARGET_DECRYPTION_AGGREGATE_OPENING: u32 =
    SetupProofFamily::TargetDecryptionAggregateOpening.stream_code();
pub(crate) const TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY: &str =
    SetupProofFamily::TargetDecryptionAggregateOpening.wire_label();

const MATERIAL_ROOT_BYTE_LENGTH: usize = 64;

#[derive(Clone)]
struct VerifiedCanonicalProofMaterial {
    proof_bytes: BgvProofMaterialBytes,
    proof_family: &'static str,
}

static VERIFIED_CANONICAL_PROOF_MATERIALS: OnceLock<
    Mutex<BTreeMap<String, VerifiedCanonicalProofMaterial>>,
> = OnceLock::new();

#[derive(Clone)]
struct VerifiedCanonicalSetupProofBinding {
    proof_family: &'static str,
    verification_binding_hash: String,
}

#[derive(Clone)]
#[cfg(test)]
pub(in crate::bgv::setup) struct CanonicalSetupProofBindingLease {
    proof_bytes_hash: String,
    binding: VerifiedCanonicalSetupProofBinding,
}

#[cfg(test)]
impl CanonicalSetupProofBindingLease {
    pub(in crate::bgv::setup) fn proof_bytes_hash(&self) -> &str {
        &self.proof_bytes_hash
    }
}

#[derive(Clone, Copy)]
pub(crate) struct AcceptedSetupProofBindingSession {
    pub(in crate::bgv::setup) session_handle: u32,
}

impl AcceptedSetupProofBindingSession {
    /// Opens a process-local verifier scope identified by a non-reused opaque
    /// handle. The handle is runtime state, never protocol input.
    pub(in crate::bgv::setup) fn begin_fresh() -> CanonicalResult<Self> {
        let mut registry = accepted_setup_proof_binding_session_registry()
            .lock()
            .map_err(|_| canonical_proof_store_error())?;
        let session_handle = registry.take_session_handle()?;
        registry.sessions.insert(
            session_handle,
            AcceptedSetupProofBindingSessionState {
                bindings: BTreeMap::new(),
                component_materials: BTreeMap::new(),
                component_material_roots: BTreeSet::new(),
                proof_materials: BTreeMap::new(),
                proof_bytes_hashes: BTreeSet::new(),
                public_key_share_materials: BTreeMap::new(),
                public_key_share_material_roots: BTreeSet::new(),
            },
        );
        Ok(Self { session_handle })
    }
}

#[cfg(test)]
pub(in crate::bgv::setup) fn begin_accepted_setup_fixture_proof_binding_session()
-> CanonicalResult<AcceptedSetupProofBindingSession> {
    AcceptedSetupProofBindingSession::begin_fresh()
}

#[cfg(test)]
pub(in crate::bgv::setup) fn finish_accepted_setup_fixture_proof_binding_session(
    session: AcceptedSetupProofBindingSession,
    proof_bytes_hash: &str,
) -> CanonicalResult<CanonicalSetupProofBindingLease> {
    let lease = accepted_setup_proof_binding_lease(session.session_handle, proof_bytes_hash)?
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "accepted-setup fixture proof binding was not retained",
            )
        })?;
    cancel_accepted_setup_proof_binding_session(session.session_handle)?;
    Ok(lease)
}

struct AcceptedSetupProofBindingSessionState {
    bindings: BTreeMap<String, VerifiedCanonicalSetupProofBinding>,
    component_materials:
        BTreeMap<String, VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry>,
    component_material_roots: BTreeSet<String>,
    proof_materials: BTreeMap<String, VerifiedCanonicalProofMaterial>,
    proof_bytes_hashes: BTreeSet<String>,
    public_key_share_materials: BTreeMap<String, VerifiedCanonicalPublicKeyShareMaterialStoreEntry>,
    public_key_share_material_roots: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcceptedSetupMaterialStore {
    Component,
    Proof,
    PublicKeyShare,
}

enum AcceptedSetupMaterial {
    Component(VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry),
    Proof(VerifiedCanonicalProofMaterial),
    PublicKeyShare(VerifiedCanonicalPublicKeyShareMaterialStoreEntry),
}

fn retain_material_if_vacant<Material>(
    materials: &mut BTreeMap<String, Material>,
    material_root: String,
    material: Material,
) -> bool {
    match materials.entry(material_root) {
        Entry::Vacant(entry) => {
            entry.insert(material);
            true
        }
        Entry::Occupied(_) => false,
    }
}

impl AcceptedSetupMaterial {
    fn store(&self) -> AcceptedSetupMaterialStore {
        match self {
            Self::Component(_) => AcceptedSetupMaterialStore::Component,
            Self::Proof(_) => AcceptedSetupMaterialStore::Proof,
            Self::PublicKeyShare(_) => AcceptedSetupMaterialStore::PublicKeyShare,
        }
    }
}

impl AcceptedSetupProofBindingSessionState {
    fn material_roots(&self, store: AcceptedSetupMaterialStore) -> &BTreeSet<String> {
        match store {
            AcceptedSetupMaterialStore::Component => &self.component_material_roots,
            AcceptedSetupMaterialStore::Proof => &self.proof_bytes_hashes,
            AcceptedSetupMaterialStore::PublicKeyShare => &self.public_key_share_material_roots,
        }
    }

    fn material_roots_mut(&mut self, store: AcceptedSetupMaterialStore) -> &mut BTreeSet<String> {
        match store {
            AcceptedSetupMaterialStore::Component => &mut self.component_material_roots,
            AcceptedSetupMaterialStore::Proof => &mut self.proof_bytes_hashes,
            AcceptedSetupMaterialStore::PublicKeyShare => &mut self.public_key_share_material_roots,
        }
    }

    fn retains_material_root(
        &self,
        store: AcceptedSetupMaterialStore,
        material_root: &str,
    ) -> bool {
        match store {
            AcceptedSetupMaterialStore::Component => {
                self.component_materials.contains_key(material_root)
            }
            AcceptedSetupMaterialStore::Proof => self.proof_materials.contains_key(material_root),
            AcceptedSetupMaterialStore::PublicKeyShare => {
                self.public_key_share_materials.contains_key(material_root)
            }
        }
    }

    fn owns_material_root(&self, store: AcceptedSetupMaterialStore, material_root: &str) -> bool {
        self.material_roots(store).contains(material_root)
            || self.retains_material_root(store, material_root)
    }

    fn retain_material(
        &mut self,
        material_root: String,
        material: AcceptedSetupMaterial,
    ) -> CanonicalResult<()> {
        let store = material.store();
        if !self.material_roots_mut(store).remove(&material_root) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "accepted-setup material root is not reserved by this session",
            ));
        }
        let was_vacant = match material {
            AcceptedSetupMaterial::Component(material) => {
                retain_material_if_vacant(&mut self.component_materials, material_root, material)
            }
            AcceptedSetupMaterial::Proof(material) => {
                retain_material_if_vacant(&mut self.proof_materials, material_root, material)
            }
            AcceptedSetupMaterial::PublicKeyShare(material) => retain_material_if_vacant(
                &mut self.public_key_share_materials,
                material_root,
                material,
            ),
        };
        if !was_vacant {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "accepted-setup material root is already retained by this session",
            ));
        }
        Ok(())
    }
}

struct AcceptedSetupProofBindingSessionRegistry {
    sessions: BTreeMap<u32, AcceptedSetupProofBindingSessionState>,
    next_session_handle: Option<u32>,
}

impl Default for AcceptedSetupProofBindingSessionRegistry {
    fn default() -> Self {
        Self {
            sessions: BTreeMap::new(),
            next_session_handle: Some(1),
        }
    }
}

impl AcceptedSetupProofBindingSessionRegistry {
    fn session(
        &self,
        session_handle: u32,
    ) -> CanonicalResult<&AcceptedSetupProofBindingSessionState> {
        self.sessions.get(&session_handle).ok_or_else(|| {
            invalid_setup_proof_binding_session("accepted-setup proof binding session is invalid")
        })
    }

    fn session_mut(
        &mut self,
        session_handle: u32,
    ) -> CanonicalResult<&mut AcceptedSetupProofBindingSessionState> {
        self.sessions.get_mut(&session_handle).ok_or_else(|| {
            invalid_setup_proof_binding_session("accepted-setup proof binding session is invalid")
        })
    }

    fn take_owned_session(
        &mut self,
        session_handle: u32,
    ) -> CanonicalResult<AcceptedSetupProofBindingSessionState> {
        self.session(session_handle)?;
        Ok(self
            .sessions
            .remove(&session_handle)
            .expect("active accepted-setup proof binding session remains present"))
    }

    fn take_session_handle(&mut self) -> CanonicalResult<u32> {
        let session_handle = self.next_session_handle.ok_or_else(|| {
            invalid_setup_proof_binding_session(
                "accepted-setup proof binding session handles are exhausted",
            )
        })?;
        self.next_session_handle = session_handle.checked_add(1);
        Ok(session_handle)
    }
}

static ACCEPTED_SETUP_PROOF_BINDING_SESSION_REGISTRY: OnceLock<
    Mutex<AcceptedSetupProofBindingSessionRegistry>,
> = OnceLock::new();

fn accepted_setup_proof_binding_session_registry()
-> &'static Mutex<AcceptedSetupProofBindingSessionRegistry> {
    ACCEPTED_SETUP_PROOF_BINDING_SESSION_REGISTRY
        .get_or_init(|| Mutex::new(AcceptedSetupProofBindingSessionRegistry::default()))
}

/// Opens a verifier-owned scope for all material consumed while one
/// accepted-setup package is verified.
pub(crate) fn begin_accepted_setup_proof_binding_session() -> CanonicalResult<u32> {
    Ok(AcceptedSetupProofBindingSession::begin_fresh()?.session_handle)
}

pub(crate) fn active_accepted_setup_proof_binding_session(
    session_handle: u32,
) -> CanonicalResult<AcceptedSetupProofBindingSession> {
    accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?
        .session(session_handle)?;
    Ok(AcceptedSetupProofBindingSession { session_handle })
}

fn reserve_accepted_setup_material_root(
    session_handle: u32,
    store: AcceptedSetupMaterialStore,
    material_root: &str,
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    registry.session(session_handle)?;
    if registry.sessions.iter().any(|(other_handle, session)| {
        *other_handle != session_handle && session.owns_material_root(store, material_root)
    }) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup material root is already owned by another session",
        ));
    }
    let session = registry.session_mut(session_handle)?;
    if session.retains_material_root(store, material_root) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup material root is already retained by this session",
        ));
    }
    if !session
        .material_roots_mut(store)
        .insert(material_root.to_string())
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup material root is already reserved by this session",
        ));
    }
    Ok(())
}

fn release_accepted_setup_material_root(
    session_handle: u32,
    store: AcceptedSetupMaterialStore,
    material_root: &str,
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session_mut(session_handle)?;
    if !session.material_roots_mut(store).remove(material_root) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup material root is not owned by this session",
        ));
    }
    Ok(())
}

fn retain_accepted_setup_material(
    session_handle: u32,
    material_root: String,
    material: AcceptedSetupMaterial,
) -> CanonicalResult<()> {
    accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?
        .session_mut(session_handle)?
        .retain_material(material_root, material)
}

#[cfg(test)]
fn accepted_setup_session_owns_material_root(
    session_handle: u32,
    store: AcceptedSetupMaterialStore,
    material_root: &str,
) -> CanonicalResult<bool> {
    let registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session(session_handle)?;
    Ok(session.owns_material_root(store, material_root))
}

pub(in crate::bgv::setup) fn accepted_setup_public_key_share_material(
    session_handle: u32,
    material_root: &str,
) -> CanonicalResult<Option<super::accepted_setup::VerifiedCanonicalPublicKeyShareMaterialHandle>> {
    let registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session(session_handle)?;
    Ok(session
        .public_key_share_materials
        .get(material_root)
        .map(|entry| Arc::clone(&entry.material)))
}

pub(in crate::bgv::setup) fn take_accepted_setup_proof_material_bytes(
    session_handle: u32,
    proof_family: &str,
    proof_bytes_hash: &str,
) -> CanonicalResult<Option<SetupProofMaterialBytes>> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session_mut(session_handle)?;
    let Some(material) = session.proof_materials.get(proof_bytes_hash) else {
        return Ok(None);
    };
    if material.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof bytes hash belongs to a different proof family",
        ));
    }
    Ok(session
        .proof_materials
        .remove(proof_bytes_hash)
        .map(|material| material.proof_bytes))
}

pub(in crate::bgv::setup) fn accepted_setup_component_material(
    session_handle: u32,
    proof_family: &str,
    material_root: &str,
) -> CanonicalResult<Option<VerifiedEvaluationKeyShareComponentMaterialChunkStoreEntry>> {
    let registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session(session_handle)?;
    let Some(material) = session.component_materials.get(material_root) else {
        return Ok(None);
    };
    if material.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup component material root belongs to a different proof family",
        ));
    }
    Ok(Some(material.clone()))
}

/// Replaces authenticated proof bytes with the semantic binding recomputed by
/// the verifier inside one accepted-setup session.
#[cfg(test)]
pub(in crate::bgv::setup) fn retain_accepted_setup_proof_binding(
    session_handle: u32,
    proof_family: &'static str,
    proof_bytes_hash: &str,
    verification_binding_hash: String,
) -> CanonicalResult<()> {
    let mut session_registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = session_registry.session_mut(session_handle)?;
    if session.bindings.contains_key(proof_bytes_hash) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof bytes hash is already retained by this session",
        ));
    }

    {
        let mut materials = verified_canonical_proof_materials()
            .lock()
            .map_err(|_| canonical_proof_store_error())?;
        let material = materials.get(proof_bytes_hash).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "accepted-setup proof binding requires authenticated proof bytes",
            )
        })?;
        if material.proof_family != proof_family {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "canonical setup proof bytes hash belongs to a different proof family",
            ));
        }
        materials
            .remove(proof_bytes_hash)
            .expect("authenticated setup proof material remains present");
    }

    session.bindings.insert(
        proof_bytes_hash.to_string(),
        VerifiedCanonicalSetupProofBinding {
            proof_family,
            verification_binding_hash,
        },
    );
    Ok(())
}

/// Consumes a verifier-derived semantic binding only from its owning flow.
/// Exact family and statement binding mismatches do not consume the entry so a
/// caller cannot destroy valid state by guessing roots.
pub(in crate::bgv::setup) fn consume_accepted_setup_proof_binding(
    session_handle: u32,
    proof_family: &str,
    proof_bytes_hash: &str,
    verification_binding_hash: &str,
) -> CanonicalResult<bool> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session_mut(session_handle)?;
    let Some(binding) = session.bindings.get(proof_bytes_hash) else {
        return Ok(false);
    };
    if binding.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof bytes hash belongs to a different proof family",
        ));
    }
    if binding.verification_binding_hash != verification_binding_hash {
        return Ok(false);
    }
    session.bindings.remove(proof_bytes_hash);
    Ok(true)
}

/// Captures verifier-owned state for deterministic test fixtures without
/// publishing a serialized acceptance receipt. Production callers must stream
/// and verify proof bytes afresh inside their own session.
#[cfg(test)]
pub(in crate::bgv::setup) fn accepted_setup_proof_binding_lease(
    session_handle: u32,
    proof_bytes_hash: &str,
) -> CanonicalResult<Option<CanonicalSetupProofBindingLease>> {
    let registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session(session_handle)?;
    Ok(session
        .bindings
        .get(proof_bytes_hash)
        .cloned()
        .map(|binding| CanonicalSetupProofBindingLease {
            proof_bytes_hash: proof_bytes_hash.to_string(),
            binding,
        }))
}

/// Restores a deterministic test fixture's opaque verifier state into the
/// fresh verifier scope for the current verification flow.
#[cfg(test)]
pub(in crate::bgv::setup) fn restore_accepted_setup_proof_binding_lease(
    session_handle: u32,
    lease: &CanonicalSetupProofBindingLease,
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session_mut(session_handle)?;
    match session.bindings.entry(lease.proof_bytes_hash.clone()) {
        Entry::Vacant(entry) => {
            entry.insert(lease.binding.clone());
            Ok(())
        }
        Entry::Occupied(entry)
            if entry.get().proof_family == lease.binding.proof_family
                && entry.get().verification_binding_hash
                    == lease.binding.verification_binding_hash =>
        {
            Ok(())
        }
        Entry::Occupied(_) => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof binding lease conflicts with retained session state",
        )),
    }
}

/// Completes a session after terminal verification consumed every retained
/// binding. Incomplete completion still destroys the session and its state.
pub(in crate::bgv::setup) fn finish_accepted_setup_proof_binding_session(
    session_handle: u32,
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.take_owned_session(session_handle)?;
    drop(registry);
    let has_unconsumed_bindings = !session.bindings.is_empty();
    let discard_result = discard_accepted_setup_session_material(session);
    if has_unconsumed_bindings {
        discard_result?;
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof binding session finished with unconsumed proofs",
        ));
    }
    discard_result
}

/// Cancels a session on every refusal or caller abort and discards all retained
/// semantic state.
pub(crate) fn cancel_accepted_setup_proof_binding_session(
    session_handle: u32,
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.take_owned_session(session_handle)?;
    drop(registry);
    discard_accepted_setup_session_material(session)
}

fn discard_accepted_setup_session_material(
    session: AcceptedSetupProofBindingSessionState,
) -> CanonicalResult<()> {
    crate::bgv::setup::evaluation_key_share_material::discard_session_component_material(
        session.component_materials,
    )
}

fn invalid_setup_proof_binding_session(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

fn verified_canonical_proof_materials()
-> &'static Mutex<BTreeMap<String, VerifiedCanonicalProofMaterial>> {
    VERIFIED_CANONICAL_PROOF_MATERIALS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn verified_canonical_setup_proof_material_bytes(
    proof_family: &str,
    proof_bytes_hash: &str,
) -> CanonicalResult<Option<SetupProofMaterialBytes>> {
    verified_canonical_proof_material_bytes(proof_family, proof_bytes_hash)
}

pub(crate) fn verified_canonical_proof_material_bytes(
    proof_family: &str,
    proof_bytes_hash: &str,
) -> CanonicalResult<Option<BgvProofMaterialBytes>> {
    let materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let Some(material) = materials.get(proof_bytes_hash) else {
        return Ok(None);
    };
    if material.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical setup proof bytes hash belongs to a different proof family",
        ));
    }
    Ok(Some(Arc::clone(&material.proof_bytes)))
}

pub(crate) fn take_verified_canonical_proof_material_bytes(
    proof_family: &str,
    proof_bytes_hash: &str,
) -> CanonicalResult<Option<BgvProofMaterialBytes>> {
    let mut materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let Some(material) = materials.get(proof_bytes_hash) else {
        return Ok(None);
    };
    if material.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical proof bytes hash belongs to a different proof family",
        ));
    }
    Ok(materials
        .remove(proof_bytes_hash)
        .map(|material| material.proof_bytes))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn evict_verified_canonical_setup_proof_materials(
    proof_bytes_hashes: &[String],
) {
    evict_verified_canonical_proof_materials(proof_bytes_hashes);
}

#[cfg(test)]
pub(crate) fn evict_verified_canonical_proof_materials(proof_bytes_hashes: &[String]) {
    let Ok(mut materials) = verified_canonical_proof_materials().lock() else {
        return;
    };
    for proof_bytes_hash in proof_bytes_hashes {
        materials.remove(proof_bytes_hash);
    }
}

pub(crate) fn retain_generated_canonical_proof_material(
    proof_family: &'static str,
    proof_bytes_hash: String,
    proof_bytes: Vec<u8>,
) -> CanonicalResult<BgvProofMaterialBytes> {
    validate_generated_proof_stream(proof_family, &proof_bytes)?;
    let proof_bytes = Arc::new(CanonicalProofMaterialBytes::from_contiguous(proof_bytes)?);
    let mut materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    match materials.entry(proof_bytes_hash) {
        Entry::Vacant(entry) => {
            entry.insert(VerifiedCanonicalProofMaterial {
                proof_bytes: Arc::clone(&proof_bytes),
                proof_family,
            });
            Ok(proof_bytes)
        }
        Entry::Occupied(_) => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical generated proof bytes hash is already retained",
        )),
    }
}

fn validate_generated_proof_stream(proof_family: &str, proof_bytes: &[u8]) -> CanonicalResult<()> {
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
    verifier.finish_with_summary().into_result().map_err(|_| {
        canonical_stream_summary_error("generated proof stream did not finish completely")
    })?;

    Ok(())
}

fn proof_material_stream_domain(proof_family: &str) -> CanonicalResult<CanonicalStreamDomain> {
    SetupProofFamily::from_wire_label(proof_family)
        .map(SetupProofFamily::stream_domain)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "canonical proof material family has no stream domain",
            )
        })
}

fn canonical_stream_summary_error(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

enum BgvCanonicalStreamSink {
    ProofMaterial {
        chunks: Vec<Vec<u8>>,
        proof_family: &'static str,
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

    fn finish(
        self,
        stream_summary: Arc<VerifiedCanonicalStreamSummary>,
    ) -> CanonicalResult<AcceptedSetupMaterial> {
        match self {
            Self::ProofMaterial {
                chunks,
                proof_family,
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
                Ok(AcceptedSetupMaterial::Proof(
                    VerifiedCanonicalProofMaterial {
                        proof_bytes,
                        proof_family,
                    },
                ))
            }
            Self::EvaluationKeyComponent(stream) => Ok(AcceptedSetupMaterial::Component(
                finish_verified_canonical_component_material_stream(stream, stream_summary)?,
            )),
            Self::PublicKeyShareMaterial(stream) => Ok(AcceptedSetupMaterial::PublicKeyShare(
                finish_verified_canonical_public_key_share_material_stream(stream, stream_summary)?,
            )),
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
    handle: u32,
    material_root: String,
    owner: Option<AcceptedSetupStreamOwner>,
    sink: BgvCanonicalStreamSink,
}

#[derive(Clone)]
struct AcceptedSetupStreamOwner {
    material_root: String,
    session: AcceptedSetupProofBindingSession,
    store: AcceptedSetupMaterialStore,
}

impl AcceptedSetupStreamOwner {
    fn release(self) -> CanonicalResult<()> {
        release_accepted_setup_material_root(
            self.session.session_handle,
            self.store,
            &self.material_root,
        )
    }
}

struct BgvCanonicalMaterialReaderSession {
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

    fn take_owned_stream_session(&mut self, handle: u32) -> Result<BgvCanonicalStreamSession, u32> {
        let Some(active_session) = self.active_session.as_ref() else {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        };
        if active_session.handle != handle {
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
    ) -> Result<BgvCanonicalMaterialReaderSession, u32> {
        let Some(reader) = self.active_material_reader.as_ref() else {
            return Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION);
        };
        if reader.handle != handle {
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
) -> Result<CanonicalStreamRuntimeBegin, u32> {
    begin_bgv_canonical_stream_inner(family_code, material_root, descriptor_bytes, None)
}

pub(crate) fn begin_accepted_setup_canonical_stream(
    family_code: u32,
    material_root: &[u8],
    descriptor_bytes: &[u8],
    accepted_setup_session: AcceptedSetupProofBindingSession,
) -> Result<CanonicalStreamRuntimeBegin, u32> {
    if material_root.len() != MATERIAL_ROOT_BYTE_LENGTH {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let store = accepted_setup_material_store(family_code)
        .ok_or_else(|| refusal_status(RefusalReason::WrongTypeOrLength))?;
    let material_root_hex = to_hex(material_root);
    reserve_accepted_setup_material_root(
        accepted_setup_session.session_handle,
        store,
        &material_root_hex,
    )
    .map_err(|_| CANONICAL_STREAM_RUNTIME_INVALID_SESSION)?;
    let owner = AcceptedSetupStreamOwner {
        material_root: material_root_hex,
        session: accepted_setup_session,
        store,
    };
    match begin_bgv_canonical_stream_inner(
        family_code,
        material_root,
        descriptor_bytes,
        Some(owner.clone()),
    ) {
        Ok(begin) => Ok(begin),
        Err(error) => {
            owner
                .release()
                .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
            Err(error)
        }
    }
}

fn accepted_setup_material_store(family_code: u32) -> Option<AcceptedSetupMaterialStore> {
    match stream_family(family_code).ok()?.kind {
        StreamFamilyKind::ProofMaterial { .. } => Some(AcceptedSetupMaterialStore::Proof),
        StreamFamilyKind::EvaluationKeyComponent { .. } => {
            Some(AcceptedSetupMaterialStore::Component)
        }
        StreamFamilyKind::PublicKeyShareMaterial => {
            Some(AcceptedSetupMaterialStore::PublicKeyShare)
        }
    }
}

fn begin_bgv_canonical_stream_inner(
    family_code: u32,
    material_root: &[u8],
    descriptor_bytes: &[u8],
    owner: Option<AcceptedSetupStreamOwner>,
) -> Result<CanonicalStreamRuntimeBegin, u32> {
    if material_root.len() != MATERIAL_ROOT_BYTE_LENGTH {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let family = stream_family(family_code)?;
    let mut registry = lock_registry()?;
    registry.refuse_overlapping_transaction()?;

    let begin =
        begin_canonical_stream_verifier(family.stream_domain.canonical_code(), descriptor_bytes)?;
    if matches!(
        &family.kind,
        StreamFamilyKind::ProofMaterial { proof_family }
            if *proof_family == TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY
    ) && usize::try_from(begin.total_byte_length).ok()
        != Some(crate::bgv::parameters::POLYNOMIAL_DEGREE * std::mem::size_of::<u64>())
    {
        let _ = cancel_canonical_stream(begin.handle);
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
    let material_root = to_hex(material_root);
    let sink = match family.kind {
        StreamFamilyKind::ProofMaterial { proof_family } => {
            if owner.is_none()
                && verified_canonical_proof_materials()
                    .lock()
                    .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?
                    .contains_key(&material_root)
            {
                let _ = cancel_canonical_stream(begin.handle);
                return Err(refusal_status(RefusalReason::ConsumedState));
            }
            BgvCanonicalStreamSink::ProofMaterial {
                chunks: Vec::new(),
                proof_family,
            }
        }
        StreamFamilyKind::EvaluationKeyComponent { proof_family } => {
            let component_stream = begin_verified_canonical_component_material_stream(
                begin.handle,
                proof_family,
                u64::from(begin.total_byte_length),
            )
            .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
            match component_stream {
                Ok(component_stream) => {
                    BgvCanonicalStreamSink::EvaluationKeyComponent(component_stream)
                }
                Err(error) => {
                    let _ = cancel_canonical_stream(begin.handle);
                    return Err(error);
                }
            }
        }
        StreamFamilyKind::PublicKeyShareMaterial => {
            let material_stream = begin_verified_canonical_public_key_share_material_stream(
                u64::from(begin.total_byte_length),
            )
            .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
            match material_stream {
                Ok(material_stream) => {
                    BgvCanonicalStreamSink::PublicKeyShareMaterial(material_stream)
                }
                Err(error) => {
                    let _ = cancel_canonical_stream(begin.handle);
                    return Err(error);
                }
            }
        }
    };
    registry.active_session = Some(BgvCanonicalStreamSession {
        handle: begin.handle,
        material_root,
        owner,
        sink,
    });
    Ok(begin)
}

pub(crate) fn absorb_bgv_canonical_stream_chunk(
    handle: u32,
    chunk_index: u32,
    chunk_bytes: &[u8],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let mut session = registry.take_owned_stream_session(handle)?;
    let canonical_result = absorb_canonical_stream_chunk(handle, chunk_index, chunk_bytes);
    if let Err(error) = canonical_result {
        session.sink.cancel();
        if let Some(owner) = session.owner {
            owner
                .release()
                .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
        }
        return Err(error);
    }
    if session.sink.absorb(chunk_bytes).is_err() {
        let _ = cancel_canonical_stream(handle);
        session.sink.cancel();
        if let Some(owner) = session.owner {
            owner
                .release()
                .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
        }
        return Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE);
    }
    registry.active_session = Some(session);
    Ok(())
}

pub(crate) fn finish_bgv_canonical_stream(handle: u32) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let session = registry.take_owned_stream_session(handle)?;
    let stream_summary = match finish_canonical_stream_verifier_with_summary(handle) {
        Ok(stream_summary) => Arc::new(stream_summary),
        Err(error) => {
            session.sink.cancel();
            if let Some(owner) = session.owner {
                owner
                    .release()
                    .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
            }
            return Err(error);
        }
    };
    let material_root = session.material_root;
    let owner = session.owner;
    match session.sink.finish(stream_summary) {
        Ok(material) => match owner {
            Some(owner) => retain_accepted_setup_material(
                owner.session.session_handle,
                material_root,
                material,
            )
            .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE),
            None => retain_standalone_stream_material(material_root, material)
                .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE),
        },
        Err(_) => {
            if let Some(owner) = owner {
                owner
                    .release()
                    .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
            }
            Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)
        }
    }
}

fn retain_standalone_stream_material(
    material_root: String,
    material: AcceptedSetupMaterial,
) -> CanonicalResult<()> {
    let AcceptedSetupMaterial::Proof(material) = material else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "evaluation-key and public-key share material require an accepted-setup session",
        ));
    };
    let mut materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    match materials.entry(material_root) {
        Entry::Vacant(entry) => {
            entry.insert(material);
            Ok(())
        }
        Entry::Occupied(_) => Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "canonical proof bytes hash is already retained",
        )),
    }
}

pub(crate) fn cancel_bgv_canonical_stream(handle: u32) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let active_session = registry.take_owned_stream_session(handle)?;
    let canonical_result = cancel_canonical_stream(handle);
    active_session.sink.cancel();
    if let Some(owner) = active_session.owner {
        owner
            .release()
            .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
    }
    canonical_result
}

pub(crate) fn begin_bgv_canonical_material_reader(
    family_code: u32,
    material_root: &[u8],
) -> Result<CanonicalStreamRuntimeBegin, u32> {
    if material_root.len() != MATERIAL_ROOT_BYTE_LENGTH {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
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
    chunk_index: u32,
    output: &mut [u8],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let mut reader = registry.take_owned_material_reader(handle)?;
    let chunk_index = match usize::try_from(chunk_index) {
        Ok(chunk_index) => chunk_index,
        Err(_) => {
            return terminate_material_reader_with_refusal(
                &reader,
                RefusalReason::WrongTypeOrLength,
            );
        }
    };
    if chunk_index != reader.next_chunk_index {
        return terminate_material_reader_with_refusal(&reader, RefusalReason::WrongTypeOrLength);
    }
    let Some(chunk) = reader.material.chunk(chunk_index) else {
        return terminate_material_reader_with_refusal(&reader, RefusalReason::WrongTypeOrLength);
    };
    if output.len() != chunk.len() {
        return terminate_material_reader_with_refusal(&reader, RefusalReason::WrongTypeOrLength);
    }
    output.copy_from_slice(chunk);
    reader.next_chunk_index += 1;
    registry.active_material_reader = Some(reader);

    Ok(())
}

fn terminate_material_reader_with_refusal(
    reader: &BgvCanonicalMaterialReaderSession,
    refusal_reason: RefusalReason,
) -> Result<(), u32> {
    evict_material_reader_source(reader)?;
    Err(refusal_status(refusal_reason))
}

pub(crate) fn finish_bgv_canonical_material_reader(handle: u32) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let reader = registry.take_owned_material_reader(handle)?;
    let material_was_complete = reader.next_chunk_index == reader.material.chunk_count();
    evict_material_reader_source(&reader)?;
    if !material_was_complete {
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }

    Ok(())
}

pub(crate) fn cancel_bgv_canonical_material_reader(handle: u32) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let reader = registry.take_owned_material_reader(handle)?;
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
                let _ = cancel_canonical_stream(active_session.handle);
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
    if let Some(proof_family) = SetupProofFamily::from_stream_code(family_code) {
        return Ok(StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: proof_family.wire_label(),
            },
            stream_domain: proof_family.stream_domain(),
        });
    }

    let family = match family_code {
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
        BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL => StreamFamily {
            kind: StreamFamilyKind::PublicKeyShareMaterial,
            stream_domain: CanonicalStreamDomain::PublicKeyShareMaterial,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_material() -> BgvProofMaterialBytes {
        Arc::new(
            CanonicalProofMaterialBytes::from_contiguous(vec![0x5a; 17])
                .expect("test proof material is non-empty"),
        )
    }

    fn finish_owned_public_key_share_proof_stream(
        session: AcceptedSetupProofBindingSession,
        material_root_bytes: &[u8; MATERIAL_ROOT_BYTE_LENGTH],
        proof_bytes: &[u8],
    ) -> Result<(), u32> {
        let descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::PublicKeyShareProof,
            proof_bytes,
        )
        .expect("derive proof stream descriptor")
        .encode()
        .expect("encode proof stream descriptor");
        let stream = begin_accepted_setup_canonical_stream(
            BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE,
            material_root_bytes,
            &descriptor,
            session,
        )?;
        for (chunk_index, chunk) in proof_bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            absorb_bgv_canonical_stream_chunk(
                stream.handle,
                u32::try_from(chunk_index).expect("test chunk index fits u32"),
                chunk,
            )?;
        }
        finish_bgv_canonical_stream(stream.handle)
    }

    #[test]
    fn accepted_setup_material_roots_are_session_owned_drained_and_retryable() {
        let material_root_bytes = [0xd1; MATERIAL_ROOT_BYTE_LENGTH];
        let material_root = to_hex(&material_root_bytes);
        let retained_proof_bytes = vec![0xd2; FOUNDATION_PROFILE.stream_chunk_byte_length + 17];
        let replacement_proof_bytes = vec![0xd3; FOUNDATION_PROFILE.stream_chunk_byte_length + 17];
        evict_verified_canonical_proof_materials(std::slice::from_ref(&material_root));

        let first_handle = begin_accepted_setup_proof_binding_session()
            .expect("first accepted-setup material session");
        let second_handle = begin_accepted_setup_proof_binding_session()
            .expect("second accepted-setup material session");
        let first_session = active_accepted_setup_proof_binding_session(first_handle)
            .expect("load first active session");
        let second_session = active_accepted_setup_proof_binding_session(second_handle)
            .expect("load second active session");

        finish_owned_public_key_share_proof_stream(
            first_session,
            &material_root_bytes,
            &retained_proof_bytes,
        )
        .expect("first session finishes its owned proof stream");
        assert!(
            accepted_setup_session_owns_material_root(
                first_handle,
                AcceptedSetupMaterialStore::Proof,
                &material_root,
            )
            .expect("first session ownership lookup")
        );
        assert_eq!(
            finish_owned_public_key_share_proof_stream(
                first_session,
                &material_root_bytes,
                &replacement_proof_bytes,
            ),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
            "the owning session cannot reserve its retained root again",
        );
        assert_eq!(
            finish_owned_public_key_share_proof_stream(
                second_session,
                &material_root_bytes,
                &replacement_proof_bytes,
            ),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
            "another session cannot reserve the owned root",
        );
        let retained_material = take_accepted_setup_proof_material_bytes(
            first_handle,
            "public-key-share",
            &material_root,
        )
        .expect("retained proof material lookup")
        .expect("first session retains the original proof material");
        let retained_material_bytes = retained_material
            .chunks()
            .flat_map(|chunk| chunk.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            retained_material_bytes, retained_proof_bytes,
            "rejected same-session and cross-session reservations cannot replace retained bytes",
        );

        cancel_accepted_setup_proof_binding_session(first_handle)
            .expect("owning session cancellation drains material");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &material_root)
                .expect("drained proof material lookup")
                .is_none()
        );

        finish_owned_public_key_share_proof_stream(
            second_session,
            &material_root_bytes,
            &replacement_proof_bytes,
        )
        .expect("same root is reusable after owner cancellation");
        finish_accepted_setup_proof_binding_session(second_handle)
            .expect("terminal completion drains owned raw material");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &material_root)
                .expect("completed session proof material lookup")
                .is_none()
        );
    }

    #[test]
    fn accepted_setup_proof_bindings_are_one_shot_and_session_scoped() {
        let proof_bytes_hash = "c1".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        evict_verified_canonical_proof_materials(std::slice::from_ref(&proof_bytes_hash));
        retain_generated_canonical_proof_material(
            "public-key-share",
            proof_bytes_hash.clone(),
            vec![0xc1; 17],
        )
        .expect("authenticated proof material fixture");

        let first_session = crate::bgv::setup::begin_accepted_setup_proof_binding_session()
            .expect("first accepted-setup proof binding session");
        let second_session = crate::bgv::setup::begin_accepted_setup_proof_binding_session()
            .expect("second accepted-setup proof binding session");
        crate::bgv::setup::retain_accepted_setup_proof_binding(
            first_session,
            "public-key-share",
            &proof_bytes_hash,
            "binding-c1".to_string(),
        )
        .expect("retain verifier-derived binding in first session");
        let fixture_lease =
            crate::bgv::setup::accepted_setup_proof_binding_lease(first_session, &proof_bytes_hash)
                .expect("test fixture binding lookup")
                .expect("test fixture binding lease");

        assert!(
            !crate::bgv::setup::consume_accepted_setup_proof_binding(
                second_session,
                "public-key-share",
                &proof_bytes_hash,
                "binding-c1",
            )
            .expect("another valid session cannot see the first session's binding")
        );
        assert!(
            crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                "same-secret-bridge",
                &proof_bytes_hash,
                "binding-c1",
            )
            .is_err(),
            "a wrong proof family must fail without consuming the owning session's binding",
        );
        assert!(
            !crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                "public-key-share",
                &proof_bytes_hash,
                "wrong-binding",
            )
            .expect("a wrong statement binding is a non-consuming mismatch")
        );
        assert!(
            crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                "public-key-share",
                &proof_bytes_hash,
                "binding-c1",
            )
            .expect("owning session consumes its exact binding")
        );
        assert!(
            !crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                "public-key-share",
                &proof_bytes_hash,
                "binding-c1",
            )
            .expect("consumed binding is not reusable")
        );
        crate::bgv::setup::finish_accepted_setup_proof_binding_session(first_session)
            .expect("fully consumed first session finishes");
        crate::bgv::setup::finish_accepted_setup_proof_binding_session(second_session)
            .expect("empty second session finishes");

        let restored_session = crate::bgv::setup::begin_accepted_setup_proof_binding_session()
            .expect("fresh test fixture restoration session");
        crate::bgv::setup::restore_accepted_setup_proof_binding_lease(
            restored_session,
            &fixture_lease,
        )
        .expect("restore opaque verifier state into a fresh test-only session");
        assert!(
            crate::bgv::setup::consume_accepted_setup_proof_binding(
                restored_session,
                "public-key-share",
                &proof_bytes_hash,
                "binding-c1",
            )
            .expect("restored test fixture binding is owned by its fresh session")
        );
        crate::bgv::setup::finish_accepted_setup_proof_binding_session(restored_session)
            .expect("restored test fixture session finishes");
    }

    #[test]
    fn accepted_setup_proof_binding_finish_and_cancel_discard_unconsumed_state() {
        let finish_root = "c3".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        let cancel_root = "c4".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        let roots = [finish_root.clone(), cancel_root.clone()];
        evict_verified_canonical_proof_materials(&roots);
        retain_generated_canonical_proof_material(
            "public-key-share",
            finish_root.clone(),
            vec![0xc3; 17],
        )
        .expect("finish-path proof material fixture");
        retain_generated_canonical_proof_material(
            "public-key-share",
            cancel_root.clone(),
            vec![0xc4; 17],
        )
        .expect("cancel-path proof material fixture");

        let finish_session =
            begin_accepted_setup_proof_binding_session().expect("finish-path session");
        retain_accepted_setup_proof_binding(
            finish_session,
            "public-key-share",
            &finish_root,
            "finish-binding".to_string(),
        )
        .expect("retain finish-path binding");
        assert!(
            finish_accepted_setup_proof_binding_session(finish_session).is_err(),
            "finishing with unconsumed verifier state must fail closed",
        );
        assert!(
            consume_accepted_setup_proof_binding(
                finish_session,
                "public-key-share",
                &finish_root,
                "finish-binding",
            )
            .is_err(),
            "failed completion must still destroy the session",
        );

        let cancel_session =
            begin_accepted_setup_proof_binding_session().expect("cancel-path session");
        retain_accepted_setup_proof_binding(
            cancel_session,
            "public-key-share",
            &cancel_root,
            "cancel-binding".to_string(),
        )
        .expect("retain cancel-path binding");
        crate::bgv::setup::cancel_accepted_setup_proof_binding_session(cancel_session)
            .expect("owning session cancellation");
        assert!(
            consume_accepted_setup_proof_binding(
                cancel_session,
                "public-key-share",
                &cancel_root,
                "cancel-binding",
            )
            .is_err(),
            "cancelled verifier state must not remain addressable",
        );
    }

    #[test]
    fn wrong_handle_cannot_consume_bgv_stream_or_material_reader_sessions() {
        let mut registry = BgvCanonicalStreamRegistry {
            active_session: Some(BgvCanonicalStreamSession {
                handle: 41,
                material_root: "00".repeat(MATERIAL_ROOT_BYTE_LENGTH),
                owner: None,
                sink: BgvCanonicalStreamSink::ProofMaterial {
                    chunks: Vec::new(),
                    proof_family: "public-key-share",
                },
            }),
            active_material_reader: Some(BgvCanonicalMaterialReaderSession {
                handle: 57,
                material: retained_material(),
                material_root: "11".repeat(MATERIAL_ROOT_BYTE_LENGTH),
                next_chunk_index: 0,
                proof_family: "public-key-share",
            }),
            next_material_reader_handle: Some(1),
        };

        assert!(matches!(
            registry.take_owned_stream_session(42),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
        ));
        assert!(registry.active_session.is_some());
        assert!(matches!(
            registry.take_owned_material_reader(58),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
        ));
        assert!(registry.active_material_reader.is_some());
    }

    #[test]
    fn refused_overlap_preserves_the_active_bgv_transaction() {
        let registry = BgvCanonicalStreamRegistry {
            active_material_reader: Some(BgvCanonicalMaterialReaderSession {
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
        {
            let mut registry = lock_registry().expect("BGV stream registry");
            assert!(registry.active_material_reader.is_none());
            registry.active_material_reader = Some(BgvCanonicalMaterialReaderSession {
                handle: 61,
                material: Arc::clone(&finished_material),
                material_root: finished_root.clone(),
                next_chunk_index: finished_material.chunk_count(),
                proof_family: "public-key-share",
            });
        }
        finish_bgv_canonical_material_reader(61).expect("complete material reader finish");
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
        {
            let mut registry = lock_registry().expect("BGV stream registry");
            assert!(registry.active_material_reader.is_none());
            registry.active_material_reader = Some(BgvCanonicalMaterialReaderSession {
                handle: 62,
                material: cancelled_material,
                material_root: cancelled_root.clone(),
                next_chunk_index: 0,
                proof_family: "public-key-share",
            });
        }
        cancel_bgv_canonical_material_reader(62).expect("incomplete material reader cancellation");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &cancelled_root)
                .expect("cancelled material store lookup")
                .is_none()
        );
    }

    #[test]
    fn malformed_material_reader_chunks_terminate_evict_and_allow_a_clean_retry() {
        let wrong_index_root = "b1".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        let wrong_output_length_root = "b2".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        let retry_root = "b3".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        let roots = [
            wrong_index_root.clone(),
            wrong_output_length_root.clone(),
            retry_root.clone(),
        ];
        evict_verified_canonical_proof_materials(&roots);

        let retain_material = |material_root: &str, byte: u8| {
            retain_generated_canonical_proof_material(
                "public-key-share",
                material_root.to_string(),
                vec![byte; 17],
            )
            .expect("reader source material fixture");
        };
        let material_root_bytes = |material_root: &str| {
            crate::transcript_core::decode_hex(material_root)
                .expect("reader source material root is canonical hex")
        };

        retain_material(&wrong_index_root, 0x71);
        let wrong_index_reader = begin_bgv_canonical_material_reader(
            BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE,
            &material_root_bytes(&wrong_index_root),
        )
        .expect("wrong-index reader begins");
        let mut correct_length_output = [0_u8; 17];
        assert_eq!(
            read_bgv_canonical_material_chunk(
                wrong_index_reader.handle,
                1,
                &mut correct_length_output,
            ),
            Err(refusal_status(RefusalReason::WrongTypeOrLength)),
        );
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &wrong_index_root)
                .expect("wrong-index source lookup")
                .is_none()
        );

        retain_material(&wrong_output_length_root, 0x72);
        let wrong_output_length_reader = begin_bgv_canonical_material_reader(
            BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE,
            &material_root_bytes(&wrong_output_length_root),
        )
        .expect("wrong-output-length reader begins after wrong-index termination");
        let mut short_output = [0_u8; 16];
        assert_eq!(
            read_bgv_canonical_material_chunk(
                wrong_output_length_reader.handle,
                0,
                &mut short_output,
            ),
            Err(refusal_status(RefusalReason::WrongTypeOrLength)),
        );
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &wrong_output_length_root,)
                .expect("wrong-output-length source lookup")
                .is_none()
        );

        retain_material(&retry_root, 0x73);
        let retry_reader = begin_bgv_canonical_material_reader(
            BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE,
            &material_root_bytes(&retry_root),
        )
        .expect("clean retry reader begins");
        let mut retry_output = [0_u8; 17];
        read_bgv_canonical_material_chunk(retry_reader.handle, 0, &mut retry_output)
            .expect("clean retry chunk reads");
        assert_eq!(retry_output, [0x73; 17]);
        finish_bgv_canonical_material_reader(retry_reader.handle)
            .expect("clean retry reader finishes");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &retry_root)
                .expect("clean retry source lookup")
                .is_none()
        );
    }
}
