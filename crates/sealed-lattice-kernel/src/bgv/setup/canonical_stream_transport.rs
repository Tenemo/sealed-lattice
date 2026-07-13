use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
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
    hashing::to_hex,
};

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
pub(crate) const BGV_CANONICAL_STREAM_FAMILY_TARGET_DECRYPTION_AGGREGATE_OPENING: u32 = 11;
pub(crate) const TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY: &str =
    "target-decryption-aggregate-opening";

const MATERIAL_ROOT_BYTE_LENGTH: usize = 64;

#[derive(Clone)]
struct VerifiedCanonicalProofMaterial {
    proof_bytes: BgvProofMaterialBytes,
    proof_family: &'static str,
    stream_summary: Arc<VerifiedCanonicalStreamSummary>,
}

static VERIFIED_CANONICAL_PROOF_MATERIALS: OnceLock<
    Mutex<BTreeMap<String, VerifiedCanonicalProofMaterial>>,
> = OnceLock::new();

#[derive(Clone)]
struct VerifiedCanonicalSetupProofBinding {
    proof_family: &'static str,
    verification_binding_hash: String,
    stream_summary: Arc<VerifiedCanonicalStreamSummary>,
}

#[derive(Clone)]
#[cfg(test)]
pub(in crate::bgv::setup) struct CanonicalSetupProofBindingLease {
    proof_material_root: String,
    binding: VerifiedCanonicalSetupProofBinding,
}

#[derive(Clone, Copy)]
pub(crate) struct AcceptedSetupProofBindingSession {
    pub(in crate::bgv::setup) session_handle: u32,
    pub(in crate::bgv::setup) capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
}

impl AcceptedSetupProofBindingSession {
    /// Opens a process-local verifier scope without serializing any capability
    /// into the protocol request. The capability is an internal correlation
    /// token derived from the registry's non-reused handle, not a secret or a
    /// protocol authentication claim.
    #[cfg(test)]
    pub(in crate::bgv::setup) fn begin_fresh() -> CanonicalResult<Self> {
        let mut registry = accepted_setup_proof_binding_session_registry()
            .lock()
            .map_err(|_| canonical_proof_store_error())?;
        let session_handle = registry.take_session_handle()?;
        let digest = crate::hashing::hash512(
            "sealed-lattice/accepted-setup/proof-binding-session-capability",
            &[&session_handle.to_le_bytes()],
        );
        let mut capability = [0_u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        capability.copy_from_slice(&digest[..CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH]);
        registry.sessions.insert(
            session_handle,
            AcceptedSetupProofBindingSessionState {
                capability,
                bindings: BTreeMap::new(),
                component_material_roots: BTreeSet::new(),
                proof_material_roots: BTreeSet::new(),
                public_key_share_material_roots: BTreeSet::new(),
            },
        );
        Ok(Self {
            session_handle,
            capability,
        })
    }
}

#[cfg(test)]
static ACCEPTED_SETUP_FIXTURE_PROOF_BINDING_LEASES: OnceLock<
    Mutex<BTreeMap<String, CanonicalSetupProofBindingLease>>,
> = OnceLock::new();

#[cfg(test)]
fn accepted_setup_fixture_proof_binding_leases()
-> &'static Mutex<BTreeMap<String, CanonicalSetupProofBindingLease>> {
    ACCEPTED_SETUP_FIXTURE_PROOF_BINDING_LEASES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(test)]
pub(in crate::bgv::setup) fn begin_accepted_setup_fixture_proof_binding_session()
-> CanonicalResult<AcceptedSetupProofBindingSession> {
    AcceptedSetupProofBindingSession::begin_fresh()
}

#[cfg(test)]
pub(in crate::bgv::setup) fn cache_accepted_setup_fixture_proof_binding_lease(
    session: AcceptedSetupProofBindingSession,
    proof_material_root: &str,
) -> CanonicalResult<()> {
    let lease = accepted_setup_proof_binding_lease(
        session.session_handle,
        &session.capability,
        proof_material_root,
    )?
    .ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "accepted-setup fixture proof binding was not retained",
        )
    })?;
    cancel_accepted_setup_proof_binding_session(session.session_handle, &session.capability)?;
    accepted_setup_fixture_proof_binding_leases()
        .lock()
        .map_err(|_| canonical_proof_store_error())?
        .insert(proof_material_root.to_string(), lease);
    Ok(())
}

#[cfg(test)]
pub(in crate::bgv::setup) fn accepted_setup_fixture_proof_binding_lease(
    proof_material_root: &str,
) -> CanonicalResult<Option<CanonicalSetupProofBindingLease>> {
    Ok(accepted_setup_fixture_proof_binding_leases()
        .lock()
        .map_err(|_| canonical_proof_store_error())?
        .get(proof_material_root)
        .cloned())
}

struct AcceptedSetupProofBindingSessionState {
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    bindings: BTreeMap<String, VerifiedCanonicalSetupProofBinding>,
    component_material_roots: BTreeSet<String>,
    proof_material_roots: BTreeSet<String>,
    public_key_share_material_roots: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcceptedSetupMaterialStore {
    Component,
    Proof,
    PublicKeyShare,
}

impl AcceptedSetupProofBindingSessionState {
    fn material_roots(&self, store: AcceptedSetupMaterialStore) -> &BTreeSet<String> {
        match store {
            AcceptedSetupMaterialStore::Component => &self.component_material_roots,
            AcceptedSetupMaterialStore::Proof => &self.proof_material_roots,
            AcceptedSetupMaterialStore::PublicKeyShare => &self.public_key_share_material_roots,
        }
    }

    fn material_roots_mut(&mut self, store: AcceptedSetupMaterialStore) -> &mut BTreeSet<String> {
        match store {
            AcceptedSetupMaterialStore::Component => &mut self.component_material_roots,
            AcceptedSetupMaterialStore::Proof => &mut self.proof_material_roots,
            AcceptedSetupMaterialStore::PublicKeyShare => &mut self.public_key_share_material_roots,
        }
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
        capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    ) -> CanonicalResult<&AcceptedSetupProofBindingSessionState> {
        let session = self.sessions.get(&session_handle).ok_or_else(|| {
            invalid_setup_proof_binding_session("accepted-setup proof binding session is invalid")
        })?;
        if !constant_time_equal(&session.capability, capability) {
            return Err(invalid_setup_proof_binding_session(
                "accepted-setup proof binding session is invalid",
            ));
        }
        Ok(session)
    }

    fn session_mut(
        &mut self,
        session_handle: u32,
        capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    ) -> CanonicalResult<&mut AcceptedSetupProofBindingSessionState> {
        let session = self.sessions.get_mut(&session_handle).ok_or_else(|| {
            invalid_setup_proof_binding_session("accepted-setup proof binding session is invalid")
        })?;
        if !constant_time_equal(&session.capability, capability) {
            return Err(invalid_setup_proof_binding_session(
                "accepted-setup proof binding session is invalid",
            ));
        }
        Ok(session)
    }

    fn take_owned_session(
        &mut self,
        session_handle: u32,
        capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    ) -> CanonicalResult<AcceptedSetupProofBindingSessionState> {
        self.session(session_handle, capability)?;
        Ok(self
            .sessions
            .remove(&session_handle)
            .expect("authenticated accepted-setup proof binding session remains present"))
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

/// Opens a verifier-owned scope for semantic proof bindings accumulated while
/// one accepted-setup package is verified. The caller-generated capability is
/// never serialized into a protocol object and every subsequent operation must
/// authenticate it.
pub(crate) fn begin_accepted_setup_proof_binding_session(
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> CanonicalResult<u32> {
    if capability.iter().all(|byte| *byte == 0) {
        return Err(invalid_setup_proof_binding_session(
            "accepted-setup proof binding session capability must not be all zeroes",
        ));
    }
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session_handle = registry.take_session_handle()?;
    registry.sessions.insert(
        session_handle,
        AcceptedSetupProofBindingSessionState {
            capability,
            bindings: BTreeMap::new(),
            component_material_roots: BTreeSet::new(),
            proof_material_roots: BTreeSet::new(),
            public_key_share_material_roots: BTreeSet::new(),
        },
    );
    Ok(session_handle)
}

pub(crate) fn authenticated_accepted_setup_proof_binding_session(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> CanonicalResult<AcceptedSetupProofBindingSession> {
    accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?
        .session(session_handle, capability)?;
    Ok(AcceptedSetupProofBindingSession {
        session_handle,
        capability: *capability,
    })
}

pub(in crate::bgv::setup) fn reserve_accepted_setup_material_root(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    store: AcceptedSetupMaterialStore,
    material_root: &str,
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    registry.session(session_handle, capability)?;
    if registry.sessions.iter().any(|(other_handle, session)| {
        *other_handle != session_handle && session.material_roots(store).contains(material_root)
    }) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup material root is already owned by another session",
        ));
    }
    let session = registry.session_mut(session_handle, capability)?;
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

pub(in crate::bgv::setup) fn release_accepted_setup_material_root(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    store: AcceptedSetupMaterialStore,
    material_root: &str,
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session_mut(session_handle, capability)?;
    if !session.material_roots_mut(store).remove(material_root) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup material root is not owned by this session",
        ));
    }
    Ok(())
}

pub(in crate::bgv::setup) fn accepted_setup_session_owns_material_root(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    store: AcceptedSetupMaterialStore,
    material_root: &str,
) -> CanonicalResult<bool> {
    let registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    Ok(registry
        .session(session_handle, capability)?
        .material_roots(store)
        .contains(material_root))
}

/// Replaces authenticated proof bytes with the semantic binding recomputed by
/// the verifier inside one capability-owned accepted-setup session.
#[cfg(test)]
pub(in crate::bgv::setup) fn retain_accepted_setup_proof_binding(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    proof_family: &'static str,
    proof_material_root: &str,
    verification_binding_hash: String,
) -> CanonicalResult<()> {
    let mut session_registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = session_registry.session_mut(session_handle, capability)?;
    if session.bindings.contains_key(proof_material_root) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof binding root is already retained by this session",
        ));
    }

    let material = {
        let mut materials = verified_canonical_proof_materials()
            .lock()
            .map_err(|_| canonical_proof_store_error())?;
        let material = materials.get(proof_material_root).ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                "accepted-setup proof binding requires authenticated proof bytes",
            )
        })?;
        if material.proof_family != proof_family {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "canonical setup proof material root belongs to a different proof family",
            ));
        }
        materials
            .remove(proof_material_root)
            .expect("authenticated setup proof material remains present")
    };

    session.bindings.insert(
        proof_material_root.to_string(),
        VerifiedCanonicalSetupProofBinding {
            proof_family,
            verification_binding_hash,
            stream_summary: material.stream_summary,
        },
    );
    Ok(())
}

/// Consumes a verifier-derived semantic binding only from its owning flow.
/// Exact family and statement binding mismatches do not consume the entry so a
/// caller cannot destroy valid state by guessing roots.
pub(in crate::bgv::setup) fn consume_accepted_setup_proof_binding(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    proof_family: &str,
    proof_material_root: &str,
    verification_binding_hash: &str,
) -> CanonicalResult<bool> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session_mut(session_handle, capability)?;
    let Some(binding) = session.bindings.get(proof_material_root) else {
        return Ok(false);
    };
    if binding.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof binding root belongs to a different proof family",
        ));
    }
    if binding.verification_binding_hash != verification_binding_hash {
        return Ok(false);
    }
    session.bindings.remove(proof_material_root);
    Ok(true)
}

pub(in crate::bgv::setup) fn accepted_setup_proof_binding_stream_summary(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    proof_family: &str,
    proof_material_root: &str,
) -> CanonicalResult<Option<Arc<VerifiedCanonicalStreamSummary>>> {
    let registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session(session_handle, capability)?;
    let Some(binding) = session.bindings.get(proof_material_root) else {
        return Ok(None);
    };
    if binding.proof_family != proof_family {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof binding root belongs to a different proof family",
        ));
    }
    Ok(Some(Arc::clone(&binding.stream_summary)))
}

/// Captures verifier-owned state for deterministic test fixtures without
/// publishing a serialized acceptance receipt. Production callers must stream
/// and verify proof bytes afresh inside their own session.
#[cfg(test)]
pub(in crate::bgv::setup) fn accepted_setup_proof_binding_lease(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    proof_material_root: &str,
) -> CanonicalResult<Option<CanonicalSetupProofBindingLease>> {
    let registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session(session_handle, capability)?;
    Ok(session
        .bindings
        .get(proof_material_root)
        .cloned()
        .map(|binding| CanonicalSetupProofBindingLease {
            proof_material_root: proof_material_root.to_string(),
            binding,
        }))
}

/// Restores a deterministic test fixture's opaque verifier state into the
/// fresh capability scope for the current verification flow.
#[cfg(test)]
pub(in crate::bgv::setup) fn restore_accepted_setup_proof_binding_lease(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    lease: &CanonicalSetupProofBindingLease,
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.session_mut(session_handle, capability)?;
    match session.bindings.entry(lease.proof_material_root.clone()) {
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
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.take_owned_session(session_handle, capability)?;
    drop(registry);
    let drain_result = drain_accepted_setup_material_roots(&session);
    if !session.bindings.is_empty() {
        drain_result?;
        return Err(CanonicalError::new(
            CanonicalErrorCode::ComponentMismatch,
            "accepted-setup proof binding session finished with unconsumed proofs",
        ));
    }
    drain_result
}

/// Cancels a session on every refusal or caller abort. Cancellation is
/// capability-authenticated and discards all retained semantic state.
pub(crate) fn cancel_accepted_setup_proof_binding_session(
    session_handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> CanonicalResult<()> {
    let mut registry = accepted_setup_proof_binding_session_registry()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    let session = registry.take_owned_session(session_handle, capability)?;
    drop(registry);
    drain_accepted_setup_material_roots(&session)
}

fn drain_accepted_setup_material_roots(
    session: &AcceptedSetupProofBindingSessionState,
) -> CanonicalResult<()> {
    let proof_result = drain_verified_canonical_proof_materials(
        &session
            .proof_material_roots
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
    );
    let component_result =
        crate::bgv::setup::drain_verified_evaluation_key_share_component_material(
            &session
                .component_material_roots
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        );
    let public_key_share_result =
        crate::bgv::setup::drain_verified_canonical_public_key_share_materials(
            &session
                .public_key_share_material_roots
                .iter()
                .cloned()
                .collect::<Vec<_>>(),
        );
    proof_result?;
    component_result?;
    public_key_share_result
}

fn invalid_setup_proof_binding_session(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

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

pub(in crate::bgv::setup) fn authenticated_setup_proof_material_stream_summary_in_session(
    proof_binding_session: Option<&AcceptedSetupProofBindingSession>,
    proof_family: &str,
    proof_material_root: &str,
) -> CanonicalResult<Option<Arc<VerifiedCanonicalStreamSummary>>> {
    if let Some(proof_binding_session) = proof_binding_session {
        if let Some(stream_summary) = accepted_setup_proof_binding_stream_summary(
            proof_binding_session.session_handle,
            &proof_binding_session.capability,
            proof_family,
            proof_material_root,
        )? {
            return Ok(Some(stream_summary));
        }
        if !accepted_setup_session_owns_material_root(
            proof_binding_session.session_handle,
            &proof_binding_session.capability,
            AcceptedSetupMaterialStore::Proof,
            proof_material_root,
        )? {
            return Ok(None);
        }
    }
    let materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    if let Some(material) = materials.get(proof_material_root) {
        if material.proof_family != proof_family {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "canonical setup proof material root belongs to a different proof family",
            ));
        }
        return Ok(Some(Arc::clone(&material.stream_summary)));
    }
    drop(materials);

    Ok(None)
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

fn drain_verified_canonical_proof_materials(
    proof_material_roots: &[String],
) -> CanonicalResult<()> {
    let mut materials = verified_canonical_proof_materials()
        .lock()
        .map_err(|_| canonical_proof_store_error())?;
    for proof_material_root in proof_material_roots {
        materials.remove(proof_material_root);
    }
    Ok(())
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
        TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY => {
            Ok(CanonicalStreamDomain::RecipientAggregateThresholdShareProof)
        }
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
            &self.session.capability,
            self.store,
            &self.material_root,
        )
    }
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
    begin_bgv_canonical_stream_inner(
        family_code,
        material_root,
        descriptor_bytes,
        capability,
        None,
    )
}

pub(crate) fn begin_accepted_setup_canonical_stream(
    family_code: u32,
    material_root: &[u8],
    descriptor_bytes: &[u8],
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
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
        &accepted_setup_session.capability,
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
        capability,
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
    match family_code {
        BGV_CANONICAL_STREAM_FAMILY_VSS_SHARE_LINKAGE
        | BGV_CANONICAL_STREAM_FAMILY_SAME_SECRET
        | BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE
        | BGV_CANONICAL_STREAM_FAMILY_TRUSTEE_EVALUATION_KEY => {
            Some(AcceptedSetupMaterialStore::Proof)
        }
        BGV_CANONICAL_STREAM_FAMILY_RELINEARIZATION_COMPONENT
        | BGV_CANONICAL_STREAM_FAMILY_GALOIS_COMPONENT => {
            Some(AcceptedSetupMaterialStore::Component)
        }
        BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE_MATERIAL => {
            Some(AcceptedSetupMaterialStore::PublicKeyShare)
        }
        _ => None,
    }
}

fn begin_bgv_canonical_stream_inner(
    family_code: u32,
    material_root: &[u8],
    descriptor_bytes: &[u8],
    capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
    owner: Option<AcceptedSetupStreamOwner>,
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
    if matches!(
        &family.kind,
        StreamFamilyKind::ProofMaterial { proof_family }
            if *proof_family == TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY
    ) && usize::try_from(begin.total_byte_length).ok()
        != Some(crate::bgv::parameters::POLYNOMIAL_DEGREE * std::mem::size_of::<u64>())
    {
        let _ = cancel_canonical_stream(begin.handle, &capability);
        return Err(refusal_status(RefusalReason::WrongTypeOrLength));
    }
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
        owner,
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
        if let Some(owner) = session.owner {
            owner
                .release()
                .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
        }
        return Err(error);
    }
    if session.sink.absorb(chunk_bytes).is_err() {
        let _ = cancel_canonical_stream(handle, capability);
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
            if let Some(owner) = session.owner {
                owner
                    .release()
                    .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
            }
            return Err(error);
        }
    };
    match session.sink.finish(stream_summary) {
        Ok(()) => Ok(()),
        Err(_) => {
            if let Some(owner) = session.owner {
                owner
                    .release()
                    .map_err(|_| CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)?;
            }
            Err(CANONICAL_STREAM_RUNTIME_INTERNAL_FAILURE)
        }
    }
}

pub(crate) fn cancel_bgv_canonical_stream(
    handle: u32,
    capability: &[u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
) -> Result<(), u32> {
    let mut registry = lock_registry()?;
    let active_session = registry.take_owned_stream_session(handle, capability)?;
    let canonical_result = cancel_canonical_stream(handle, capability);
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
        BGV_CANONICAL_STREAM_FAMILY_TARGET_DECRYPTION_AGGREGATE_OPENING => StreamFamily {
            kind: StreamFamilyKind::ProofMaterial {
                proof_family: TARGET_DECRYPTION_AGGREGATE_OPENING_MATERIAL_FAMILY,
            },
            stream_domain: CanonicalStreamDomain::RecipientAggregateThresholdShareProof,
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

    fn finish_owned_public_key_share_proof_stream(
        session: AcceptedSetupProofBindingSession,
        material_root_bytes: &[u8; MATERIAL_ROOT_BYTE_LENGTH],
        proof_bytes: &[u8],
        stream_capability: [u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
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
            stream_capability,
            session,
        )?;
        for (chunk_index, chunk) in proof_bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            absorb_bgv_canonical_stream_chunk(
                stream.handle,
                &stream_capability,
                u32::try_from(chunk_index).expect("test chunk index fits u32"),
                chunk,
            )?;
        }
        finish_bgv_canonical_stream(stream.handle, &stream_capability)
    }

    #[test]
    fn accepted_setup_material_roots_are_session_owned_drained_and_retryable() {
        let material_root_bytes = [0xd1; MATERIAL_ROOT_BYTE_LENGTH];
        let material_root = to_hex(&material_root_bytes);
        let proof_bytes = vec![0xd2; FOUNDATION_PROFILE.stream_chunk_byte_length + 17];
        evict_verified_canonical_proof_materials(std::slice::from_ref(&material_root));

        let first_capability = [0xd3; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let second_capability = [0xd4; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let first_handle = begin_accepted_setup_proof_binding_session(first_capability)
            .expect("first accepted-setup material session");
        let second_handle = begin_accepted_setup_proof_binding_session(second_capability)
            .expect("second accepted-setup material session");
        let first_session =
            authenticated_accepted_setup_proof_binding_session(first_handle, &first_capability)
                .expect("authenticate first session");
        let second_session =
            authenticated_accepted_setup_proof_binding_session(second_handle, &second_capability)
                .expect("authenticate second session");

        finish_owned_public_key_share_proof_stream(
            first_session,
            &material_root_bytes,
            &proof_bytes,
            [0xd5; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
        )
        .expect("first session finishes its owned proof stream");
        assert!(
            accepted_setup_session_owns_material_root(
                first_handle,
                &first_capability,
                AcceptedSetupMaterialStore::Proof,
                &material_root,
            )
            .expect("first session ownership lookup")
        );
        assert!(
            authenticated_accepted_setup_proof_binding_session(
                first_handle,
                &[0x3d; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
            )
            .is_err(),
            "a wrong capability cannot authenticate the owning session",
        );
        assert_eq!(
            finish_owned_public_key_share_proof_stream(
                second_session,
                &material_root_bytes,
                &proof_bytes,
                [0xd6; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
            ),
            Err(CANONICAL_STREAM_RUNTIME_INVALID_SESSION),
            "another session cannot reserve the owned root",
        );

        cancel_accepted_setup_proof_binding_session(first_handle, &first_capability)
            .expect("owning session cancellation drains material");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &material_root)
                .expect("drained proof material lookup")
                .is_none()
        );

        finish_owned_public_key_share_proof_stream(
            second_session,
            &material_root_bytes,
            &proof_bytes,
            [0xd7; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
        )
        .expect("same root is reusable after owner cancellation");
        finish_accepted_setup_proof_binding_session(second_handle, &second_capability)
            .expect("terminal completion drains owned raw material");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &material_root)
                .expect("completed session proof material lookup")
                .is_none()
        );
    }

    #[test]
    fn accepted_setup_proof_bindings_are_one_shot_and_session_scoped() {
        assert!(
            crate::bgv::setup::begin_accepted_setup_proof_binding_session(
                [0_u8; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
            )
            .is_err(),
            "an all-zero capability must never open a verifier session",
        );
        let proof_material_root = "c1".repeat(MATERIAL_ROOT_BYTE_LENGTH);
        let first_capability = [0xc1; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let second_capability = [0xc2; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        evict_verified_canonical_proof_materials(std::slice::from_ref(&proof_material_root));
        retain_generated_canonical_proof_material(
            "public-key-share",
            proof_material_root.clone(),
            vec![0xc1; 17],
        )
        .expect("authenticated proof material fixture");

        let first_session =
            crate::bgv::setup::begin_accepted_setup_proof_binding_session(first_capability)
                .expect("first accepted-setup proof binding session");
        let second_session =
            crate::bgv::setup::begin_accepted_setup_proof_binding_session(second_capability)
                .expect("second accepted-setup proof binding session");
        crate::bgv::setup::retain_accepted_setup_proof_binding(
            first_session,
            &first_capability,
            "public-key-share",
            &proof_material_root,
            "binding-c1".to_string(),
        )
        .expect("retain verifier-derived binding in first session");
        let fixture_lease = crate::bgv::setup::accepted_setup_proof_binding_lease(
            first_session,
            &first_capability,
            &proof_material_root,
        )
        .expect("test fixture binding lookup")
        .expect("test fixture binding lease");

        assert!(
            !crate::bgv::setup::consume_accepted_setup_proof_binding(
                second_session,
                &second_capability,
                "public-key-share",
                &proof_material_root,
                "binding-c1",
            )
            .expect("another valid session cannot see the first session's binding")
        );
        assert!(
            crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                &second_capability,
                "public-key-share",
                &proof_material_root,
                "binding-c1",
            )
            .is_err(),
            "a wrong capability must not access an otherwise matching session handle",
        );
        assert!(
            crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                &first_capability,
                "same-secret-bridge",
                &proof_material_root,
                "binding-c1",
            )
            .is_err(),
            "a wrong proof family must fail without consuming the owning session's binding",
        );
        assert!(
            !crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                &first_capability,
                "public-key-share",
                &proof_material_root,
                "wrong-binding",
            )
            .expect("a wrong statement binding is a non-consuming mismatch")
        );
        assert!(
            crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                &first_capability,
                "public-key-share",
                &proof_material_root,
                "binding-c1",
            )
            .expect("owning session consumes its exact binding")
        );
        assert!(
            !crate::bgv::setup::consume_accepted_setup_proof_binding(
                first_session,
                &first_capability,
                "public-key-share",
                &proof_material_root,
                "binding-c1",
            )
            .expect("consumed binding is not reusable")
        );
        crate::bgv::setup::finish_accepted_setup_proof_binding_session(
            first_session,
            &first_capability,
        )
        .expect("fully consumed first session finishes");
        crate::bgv::setup::finish_accepted_setup_proof_binding_session(
            second_session,
            &second_capability,
        )
        .expect("empty second session finishes");

        let restored_capability = [0xc5; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let restored_session =
            crate::bgv::setup::begin_accepted_setup_proof_binding_session(restored_capability)
                .expect("fresh test fixture restoration session");
        crate::bgv::setup::restore_accepted_setup_proof_binding_lease(
            restored_session,
            &restored_capability,
            &fixture_lease,
        )
        .expect("restore opaque verifier state into a fresh test-only session");
        assert!(
            crate::bgv::setup::consume_accepted_setup_proof_binding(
                restored_session,
                &restored_capability,
                "public-key-share",
                &proof_material_root,
                "binding-c1",
            )
            .expect("restored test fixture binding is owned by its fresh session")
        );
        crate::bgv::setup::finish_accepted_setup_proof_binding_session(
            restored_session,
            &restored_capability,
        )
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

        let finish_capability = [0xc3; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let finish_session = begin_accepted_setup_proof_binding_session(finish_capability)
            .expect("finish-path session");
        retain_accepted_setup_proof_binding(
            finish_session,
            &finish_capability,
            "public-key-share",
            &finish_root,
            "finish-binding".to_string(),
        )
        .expect("retain finish-path binding");
        assert!(
            finish_accepted_setup_proof_binding_session(finish_session, &finish_capability)
                .is_err(),
            "finishing with unconsumed verifier state must fail closed",
        );
        assert!(
            consume_accepted_setup_proof_binding(
                finish_session,
                &finish_capability,
                "public-key-share",
                &finish_root,
                "finish-binding",
            )
            .is_err(),
            "failed completion must still destroy the session",
        );

        let cancel_capability = [0xc4; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let cancel_session = begin_accepted_setup_proof_binding_session(cancel_capability)
            .expect("cancel-path session");
        retain_accepted_setup_proof_binding(
            cancel_session,
            &cancel_capability,
            "public-key-share",
            &cancel_root,
            "cancel-binding".to_string(),
        )
        .expect("retain cancel-path binding");
        assert!(
            cancel_accepted_setup_proof_binding_session(
                cancel_session,
                &[0x4c; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH],
            )
            .is_err(),
            "wrong-owner cancellation must preserve the valid session",
        );
        assert!(
            crate::bgv::setup::accepted_setup_proof_binding_stream_summary(
                cancel_session,
                &cancel_capability,
                "public-key-share",
                &cancel_root,
            )
            .expect("owning session summary lookup")
            .is_some(),
        );
        crate::bgv::setup::cancel_accepted_setup_proof_binding_session(
            cancel_session,
            &cancel_capability,
        )
        .expect("owning session cancellation");
        assert!(
            accepted_setup_proof_binding_stream_summary(
                cancel_session,
                &cancel_capability,
                "public-key-share",
                &cancel_root,
            )
            .is_err(),
            "cancelled verifier state must not remain addressable",
        );
    }

    #[test]
    fn wrong_owner_cannot_consume_bgv_stream_or_material_reader_sessions() {
        let stream_capability = [0x11; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let reader_capability = [0x22; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let mut registry = BgvCanonicalStreamRegistry {
            active_session: Some(BgvCanonicalStreamSession {
                capability: stream_capability,
                handle: 41,
                owner: None,
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
        let wrong_index_capability = [0x71; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let wrong_index_reader = begin_bgv_canonical_material_reader(
            BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE,
            &material_root_bytes(&wrong_index_root),
            wrong_index_capability,
        )
        .expect("wrong-index reader begins");
        let mut correct_length_output = [0_u8; 17];
        assert_eq!(
            read_bgv_canonical_material_chunk(
                wrong_index_reader.handle,
                &wrong_index_capability,
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
        let wrong_output_length_capability = [0x72; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let wrong_output_length_reader = begin_bgv_canonical_material_reader(
            BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE,
            &material_root_bytes(&wrong_output_length_root),
            wrong_output_length_capability,
        )
        .expect("wrong-output-length reader begins after wrong-index termination");
        let mut short_output = [0_u8; 16];
        assert_eq!(
            read_bgv_canonical_material_chunk(
                wrong_output_length_reader.handle,
                &wrong_output_length_capability,
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
        let retry_capability = [0x73; CANONICAL_STREAM_CAPABILITY_BYTE_LENGTH];
        let retry_reader = begin_bgv_canonical_material_reader(
            BGV_CANONICAL_STREAM_FAMILY_PUBLIC_KEY_SHARE,
            &material_root_bytes(&retry_root),
            retry_capability,
        )
        .expect("clean retry reader begins");
        let mut retry_output = [0_u8; 17];
        read_bgv_canonical_material_chunk(
            retry_reader.handle,
            &retry_capability,
            0,
            &mut retry_output,
        )
        .expect("clean retry chunk reads");
        assert_eq!(retry_output, [0x73; 17]);
        finish_bgv_canonical_material_reader(retry_reader.handle, &retry_capability)
            .expect("clean retry reader finishes");
        assert!(
            verified_canonical_proof_material_bytes("public-key-share", &retry_root)
                .expect("clean retry source lookup")
                .is_none()
        );
    }
}
