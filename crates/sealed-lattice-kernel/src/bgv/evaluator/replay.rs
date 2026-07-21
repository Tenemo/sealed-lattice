use core::{cell::Cell, mem::size_of};
use std::rc::Rc;
use zeroize::Zeroize;

use crate::{
    bgv::{
        evaluator::{
            engine::Ciphertext,
            key_switch::{
                KeySwitchKey, KeySwitchKeyNttBuilder, KeySwitchReplayLimbPosition, relinearize,
                rotate,
            },
        },
        key_switch_topology::{KeySwitchDecompositionTopology, canonical_residue_byte_length},
        parameters::POLYNOMIAL_DEGREE,
        proof_suite::{
            KeySwitchComponentMaterialTopology, SelectedEvaluatorEntryKind,
            SelectedEvaluatorEntryPosition, VerifiedEvaluatorKeyStoreAuxiliaryMaterial,
            VerifiedEvaluatorKeyStoreMaterial,
        },
        setup::{VerifiedEvaluatorCommonComponentAuthority, VerifiedEvaluatorExecutionAuthority},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{CanonicalStreamReadbackVerifier, FOUNDATION_PROFILE, RefusalReason},
};

/// Exact range the browser must read from the already authenticated physical
/// evaluator store. The worker accepts only this next range, which keeps
/// restartable replay sequential inside one component even though the store
/// itself remains external.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorKeyStoreReadRequest {
    store_byte_offset: u64,
    byte_length: usize,
}

impl EvaluatorKeyStoreReadRequest {
    pub(crate) const fn store_byte_offset(self) -> u64 {
        self.store_byte_offset
    }

    pub(crate) const fn byte_length(self) -> usize {
        self.byte_length
    }

    #[cfg(test)]
    pub(super) const fn from_test_values(store_byte_offset: u64, byte_length: usize) -> Self {
        Self {
            store_byte_offset,
            byte_length,
        }
    }
}

/// Owns the one complete verified store carrier together with an opaque
/// retained authority for its setup-derived common components. Replays are
/// owned values so a browser worker can pause them across external-store
/// reads; the shared resident-key guard still prevents two complete keys from
/// being materialized concurrently.
pub(crate) struct VerifiedEvaluatorKeyResolver {
    common_component_authority: VerifiedEvaluatorCommonComponentAuthority,
    material: VerifiedEvaluatorKeyStoreMaterial,
    resident_key_active: Rc<Cell<bool>>,
}

impl VerifiedEvaluatorKeyResolver {
    pub(crate) fn from_execution_authority(
        execution_authority: VerifiedEvaluatorExecutionAuthority,
    ) -> Result<Self, RefusalReason> {
        let protocol_version = execution_authority.protocol_version();
        let suite_identifier = execution_authority.suite_identifier();
        let ceremony_context_hash = execution_authority.ceremony_context_hash();
        let action_context_hash = execution_authority.action_context_hash();
        let manifest_hash = execution_authority.manifest_hash();
        let roster_hash = execution_authority.roster_hash();
        let setup_proof_context_hash = execution_authority.setup_proof_context_hash();
        let evaluator_replay_context_hash = execution_authority.evaluator_replay_context_hash();
        let (verified_store, common_component_authority) =
            execution_authority.into_store_and_common_component_authority();
        let top_count = verified_store.top_count();
        if verified_store.protocol_version() != protocol_version
            || verified_store.suite_identifier() != suite_identifier
            || verified_store.ceremony_context_hash() != ceremony_context_hash
            || verified_store.action_context_hash() != action_context_hash
            || verified_store.manifest_hash() != manifest_hash
            || verified_store.roster_hash() != roster_hash
            || verified_store.setup_proof_context_hash() != setup_proof_context_hash
            || common_component_authority.evaluator_replay_context_hash()
                != evaluator_replay_context_hash
        {
            return Err(RefusalReason::WrongContext);
        }
        let material = verified_store
            .into_replay_material()
            .map_err(|_| RefusalReason::MissingPrerequisite)?;
        if material.top_count() != top_count {
            return Err(RefusalReason::WrongContext);
        }
        Ok(Self {
            common_component_authority,
            material,
            resident_key_active: Rc::new(Cell::new(false)),
        })
    }

    pub(crate) fn begin_relinearization_key_replay(
        &self,
    ) -> Result<VerifiedEvaluatorKeyReplay, RefusalReason> {
        let position = self
            .material
            .ordered_components()
            .iter()
            .map(|component| component.position())
            .find(|position| {
                matches!(
                    position.key_kind(),
                    SelectedEvaluatorEntryKind::Relinearization { .. }
                )
            })
            .ok_or(RefusalReason::MissingPrerequisite)?;
        self.begin_key_replay(position)
    }

    pub(crate) fn begin_galois_key_replay(
        &self,
        galois_element: usize,
    ) -> Result<VerifiedEvaluatorKeyReplay, RefusalReason> {
        let position = self
            .material
            .ordered_components()
            .iter()
            .map(|component| component.position())
            .find(|position| {
                matches!(
                    position.key_kind(),
                    SelectedEvaluatorEntryKind::Galois {
                        galois_element: selected_galois_element,
                        ..
                    } if selected_galois_element == galois_element
                )
            })
            .ok_or(RefusalReason::MissingPrerequisite)?;
        self.begin_key_replay(position)
    }

    fn begin_key_replay(
        &self,
        position: SelectedEvaluatorEntryPosition,
    ) -> Result<VerifiedEvaluatorKeyReplay, RefusalReason> {
        let component = self
            .material
            .component(position)
            .ok_or(RefusalReason::MissingPrerequisite)?;
        let catalog_level = selected_catalog_level(position);
        validate_material_topology(component.material().topology(), catalog_level)?;
        let runtime_pass = AuthenticatedComponentPass::new(
            component.store_byte_offset(),
            component.material().topology().clone(),
            component.material().begin_authenticated_readback()?,
        )?;
        let linked_auxiliary = component.linked_relinearization_auxiliary();
        let pending_auxiliary_pass = match position.key_kind() {
            SelectedEvaluatorEntryKind::Relinearization { .. } => {
                let linked_auxiliary =
                    linked_auxiliary.ok_or(RefusalReason::MissingPrerequisite)?;
                validate_linked_auxiliary(linked_auxiliary, catalog_level)?;
                Some(AuthenticatedComponentPass::new(
                    linked_auxiliary.store_byte_offset(),
                    linked_auxiliary.material().topology().clone(),
                    linked_auxiliary.material().begin_authenticated_readback()?,
                )?)
            }
            SelectedEvaluatorEntryKind::Galois { .. } => {
                if linked_auxiliary.is_some() {
                    return Err(RefusalReason::WrongTypeOrLength);
                }
                None
            }
        };
        let key_builder = KeySwitchKeyNttBuilder::new(catalog_level)
            .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
        let resident_key_guard =
            ResidentEvaluatorKeyGuard::acquire(Rc::clone(&self.resident_key_active))?;
        Ok(VerifiedEvaluatorKeyReplay {
            common_component_authority: self.common_component_authority.clone(),
            position,
            key_builder: Some(key_builder),
            pending_auxiliary_pass,
            phase: EvaluatorKeyReplayPhase::Runtime(runtime_pass),
            resident_key_guard: Some(resident_key_guard),
        })
    }
}

struct ResidentEvaluatorKeyGuard {
    resident_key_active: Rc<Cell<bool>>,
}

impl ResidentEvaluatorKeyGuard {
    fn acquire(resident_key_active: Rc<Cell<bool>>) -> Result<Self, RefusalReason> {
        if resident_key_active.replace(true) {
            return Err(RefusalReason::ConsumedState);
        }
        Ok(Self {
            resident_key_active,
        })
    }
}

impl Drop for ResidentEvaluatorKeyGuard {
    fn drop(&mut self) {
        self.resident_key_active.set(false);
    }
}

fn selected_catalog_level(position: SelectedEvaluatorEntryPosition) -> usize {
    match position.key_kind() {
        SelectedEvaluatorEntryKind::Relinearization { catalog_level }
        | SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => catalog_level,
    }
}

fn validate_linked_auxiliary(
    auxiliary: &VerifiedEvaluatorKeyStoreAuxiliaryMaterial,
    catalog_level: usize,
) -> Result<(), RefusalReason> {
    validate_material_topology(auxiliary.material().topology(), catalog_level)
}

fn validate_material_topology(
    material_topology: &KeySwitchComponentMaterialTopology,
    catalog_level: usize,
) -> Result<(), RefusalReason> {
    let runtime_topology = KeySwitchDecompositionTopology::for_level(catalog_level)
        .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
    if material_topology.polynomial_degree() != POLYNOMIAL_DEGREE
        || material_topology.data_block_count() != runtime_topology.data_block_count()
        || material_topology.ordered_moduli() != runtime_topology.extended_moduli()
    {
        return Err(RefusalReason::UnsupportedVersionOrSuite);
    }
    Ok(())
}

enum EvaluatorKeyReplayPhase {
    Runtime(AuthenticatedComponentPass),
    Auxiliary(AuthenticatedComponentPass),
    Complete,
    Refused(RefusalReason),
}

/// One restart-safe replay operation. Dropping it before `finish` discards all
/// partial NTT state; starting again creates fresh descriptor-authenticated
/// readback verifiers from the retained material capability.
pub(crate) struct VerifiedEvaluatorKeyReplay {
    common_component_authority: VerifiedEvaluatorCommonComponentAuthority,
    position: SelectedEvaluatorEntryPosition,
    key_builder: Option<KeySwitchKeyNttBuilder>,
    pending_auxiliary_pass: Option<AuthenticatedComponentPass>,
    phase: EvaluatorKeyReplayPhase,
    // Rust drops fields in declaration order. Keep the guard last so every
    // partial key and decoder is scrubbed before another replay can begin.
    resident_key_guard: Option<ResidentEvaluatorKeyGuard>,
}

impl Drop for VerifiedEvaluatorKeyReplay {
    fn drop(&mut self) {
        self.key_builder.take();
        self.pending_auxiliary_pass.take();
        let active_phase = core::mem::replace(
            &mut self.phase,
            EvaluatorKeyReplayPhase::Refused(RefusalReason::ConsumedState),
        );
        drop(active_phase);
        // `resident_key_guard` is declared last and is released only after
        // the builder and every active or pending decoder have been dropped.
    }
}

impl VerifiedEvaluatorKeyReplay {
    pub(crate) fn next_read_request(&self) -> Option<EvaluatorKeyStoreReadRequest> {
        match &self.phase {
            EvaluatorKeyReplayPhase::Runtime(pass) | EvaluatorKeyReplayPhase::Auxiliary(pass) => {
                pass.next_read_request()
            }
            EvaluatorKeyReplayPhase::Complete | EvaluatorKeyReplayPhase::Refused(_) => None,
        }
    }

    pub(crate) fn absorb_next_store_chunk(
        &mut self,
        store_byte_offset: u64,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        if let EvaluatorKeyReplayPhase::Refused(reason) = self.phase {
            return Err(reason);
        }
        let result = self.absorb_next_store_chunk_inner(store_byte_offset, chunk_bytes);
        if let Err(reason) = result {
            self.refuse(reason);
        }
        result
    }

    fn refuse(&mut self, reason: RefusalReason) {
        self.key_builder.take();
        self.pending_auxiliary_pass.take();
        let active_phase =
            core::mem::replace(&mut self.phase, EvaluatorKeyReplayPhase::Refused(reason));
        drop(active_phase);
    }

    fn absorb_next_store_chunk_inner(
        &mut self,
        store_byte_offset: u64,
        chunk_bytes: &[u8],
    ) -> Result<(), RefusalReason> {
        let completed_phase = match &mut self.phase {
            EvaluatorKeyReplayPhase::Runtime(pass) => {
                pass.absorb_next_chunk(
                    store_byte_offset,
                    chunk_bytes,
                    self.key_builder
                        .as_mut()
                        .ok_or(RefusalReason::ConsumedState)?,
                    KeySwitchPolynomialPass::Runtime,
                )?;
                pass.is_complete()
            }
            EvaluatorKeyReplayPhase::Auxiliary(pass) => {
                pass.absorb_next_chunk(
                    store_byte_offset,
                    chunk_bytes,
                    self.key_builder
                        .as_mut()
                        .ok_or(RefusalReason::ConsumedState)?,
                    KeySwitchPolynomialPass::Auxiliary,
                )?;
                pass.is_complete()
            }
            EvaluatorKeyReplayPhase::Complete => return Err(RefusalReason::ConsumedState),
            EvaluatorKeyReplayPhase::Refused(reason) => return Err(*reason),
        };
        if completed_phase {
            self.advance_completed_phase()?;
        }
        Ok(())
    }

    fn advance_completed_phase(&mut self) -> Result<(), RefusalReason> {
        let completed = core::mem::replace(&mut self.phase, EvaluatorKeyReplayPhase::Complete);
        match completed {
            EvaluatorKeyReplayPhase::Runtime(pass) => {
                pass.finish()?;
                match self.position.key_kind() {
                    SelectedEvaluatorEntryKind::Relinearization { .. } => {
                        self.phase = EvaluatorKeyReplayPhase::Auxiliary(
                            self.pending_auxiliary_pass
                                .take()
                                .ok_or(RefusalReason::MissingPrerequisite)?,
                        );
                    }
                    SelectedEvaluatorEntryKind::Galois { .. } => {
                        if self.pending_auxiliary_pass.is_some() {
                            return Err(RefusalReason::WrongTypeOrLength);
                        }
                        self.derive_galois_auxiliary_limbs()?;
                    }
                }
            }
            EvaluatorKeyReplayPhase::Auxiliary(pass) => {
                pass.finish()?;
            }
            EvaluatorKeyReplayPhase::Complete => return Err(RefusalReason::ConsumedState),
            EvaluatorKeyReplayPhase::Refused(reason) => return Err(reason),
        }
        Ok(())
    }

    fn derive_galois_auxiliary_limbs(&mut self) -> Result<(), RefusalReason> {
        let builder = self
            .key_builder
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?;
        while let Some(position) = builder.next_auxiliary_limb() {
            let coefficients = self
                .common_component_authority
                .sample_galois_common_component_limb(
                    self.position,
                    position.block_index(),
                    position.extended_limb_index(),
                )
                .map_err(|_| RefusalReason::WrongContext)?;
            builder
                .absorb_auxiliary_limb(coefficients)
                .map_err(canonical_replay_refusal)?;
        }
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<VerifiedEvaluatorKeyContext, RefusalReason> {
        match &self.phase {
            EvaluatorKeyReplayPhase::Complete => {}
            EvaluatorKeyReplayPhase::Refused(reason) => return Err(*reason),
            EvaluatorKeyReplayPhase::Runtime(_) | EvaluatorKeyReplayPhase::Auxiliary(_) => {
                return Err(RefusalReason::WrongTypeOrLength);
            }
        }
        let key_builder = self
            .key_builder
            .take()
            .ok_or(RefusalReason::ConsumedState)?;
        let ntt_transform_count = key_builder
            .transformed_limb_count()
            .map_err(canonical_replay_refusal)?;
        let key = key_builder.finish().map_err(canonical_replay_refusal)?;
        Ok(VerifiedEvaluatorKeyContext {
            evaluator_replay_context_hash: self
                .common_component_authority
                .evaluator_replay_context_hash(),
            _resident_key_guard: self
                .resident_key_guard
                .take()
                .ok_or(RefusalReason::ConsumedState)?,
            position: self.position,
            key,
            ntt_transform_count,
        })
    }
}

/// The sole resident production key context. Its guard is released only when
/// this value is dropped, enforcing the measured one-key-at-a-time evaluator
/// topology without a self-referential browser-worker state.
pub(crate) struct VerifiedEvaluatorKeyContext {
    evaluator_replay_context_hash: [u8; 64],
    _resident_key_guard: ResidentEvaluatorKeyGuard,
    position: SelectedEvaluatorEntryPosition,
    key: KeySwitchKey,
    ntt_transform_count: usize,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VerifiedContextDropObservation {
    retained_word_count_before_drop: usize,
    catalog_word_count_before_drop: usize,
    key_cleared_while_resident_guard_was_active: bool,
}

#[cfg(test)]
thread_local! {
    static VERIFIED_CONTEXT_DROP_OBSERVATIONS:
        std::cell::RefCell<Vec<VerifiedContextDropObservation>> = const {
            std::cell::RefCell::new(Vec::new())
        };
}

#[cfg(test)]
fn clear_verified_context_drop_observations() {
    VERIFIED_CONTEXT_DROP_OBSERVATIONS.with(|observations| observations.borrow_mut().clear());
}

#[cfg(test)]
fn take_verified_context_drop_observations() -> Vec<VerifiedContextDropObservation> {
    VERIFIED_CONTEXT_DROP_OBSERVATIONS
        .with(|observations| core::mem::take(&mut *observations.borrow_mut()))
}

impl VerifiedEvaluatorKeyContext {
    pub(crate) const fn position(&self) -> SelectedEvaluatorEntryPosition {
        self.position
    }

    pub(crate) fn relinearize(&self, ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
        if !matches!(
            self.position.key_kind(),
            SelectedEvaluatorEntryKind::Relinearization { .. }
        ) {
            return Err(wrong_evaluator_key_role());
        }
        relinearize(ciphertext, &self.key)
    }

    pub(crate) fn rotate(&self, ciphertext: &Ciphertext) -> CanonicalResult<Ciphertext> {
        let SelectedEvaluatorEntryKind::Galois { galois_element, .. } = self.position.key_kind()
        else {
            return Err(wrong_evaluator_key_role());
        };
        rotate(ciphertext, galois_element, &self.key)
    }

    pub(crate) const fn resolver_context_hash(&self) -> [u8; 64] {
        self.evaluator_replay_context_hash
    }

    pub(crate) const fn ntt_transform_count(&self) -> usize {
        self.ntt_transform_count
    }
}

impl Zeroize for VerifiedEvaluatorKeyContext {
    fn zeroize(&mut self) {
        self.evaluator_replay_context_hash.zeroize();
        self.key.zeroize();
        self.ntt_transform_count.zeroize();
    }
}

impl Drop for VerifiedEvaluatorKeyContext {
    fn drop(&mut self) {
        // Clear the key before field destruction releases the resident-key
        // guard and permits another replay to acquire the worker slot.
        #[cfg(test)]
        let observation = VerifiedContextDropObservation {
            retained_word_count_before_drop: self.key.retained_word_count(),
            catalog_word_count_before_drop: self.key.catalog_word_count(),
            key_cleared_while_resident_guard_was_active: false,
        };
        self.zeroize();
        #[cfg(test)]
        VERIFIED_CONTEXT_DROP_OBSERVATIONS.with(|observations| {
            observations
                .borrow_mut()
                .push(VerifiedContextDropObservation {
                    key_cleared_while_resident_guard_was_active: self
                        .key
                        .all_owned_buffers_are_cleared()
                        && self._resident_key_guard.resident_key_active.get(),
                    ..observation
                });
        });
    }
}

fn wrong_evaluator_key_role() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        "resident evaluator key has the wrong operation role",
    )
}

#[derive(Clone, Copy)]
enum KeySwitchPolynomialPass {
    Runtime,
    Auxiliary,
}

struct AuthenticatedComponentPass {
    store_byte_offset: u64,
    total_byte_length: u64,
    next_chunk_index: usize,
    readback: Option<CanonicalStreamReadbackVerifier>,
    decoder: KeySwitchComponentByteDecoder,
}

impl AuthenticatedComponentPass {
    fn new(
        store_byte_offset: u64,
        topology: KeySwitchComponentMaterialTopology,
        readback: CanonicalStreamReadbackVerifier,
    ) -> Result<Self, RefusalReason> {
        let total_byte_length = topology.expected_byte_length();
        if total_byte_length == 0 {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            store_byte_offset,
            total_byte_length,
            next_chunk_index: 0,
            readback: Some(readback),
            decoder: KeySwitchComponentByteDecoder::new(topology)?,
        })
    }

    fn next_read_request(&self) -> Option<EvaluatorKeyStoreReadRequest> {
        if self.is_complete() {
            return None;
        }
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let local_byte_offset = self.next_chunk_index.checked_mul(chunk_byte_length)?;
        let local_byte_offset_u64 = u64::try_from(local_byte_offset).ok()?;
        let remaining = self.total_byte_length.checked_sub(local_byte_offset_u64)?;
        let byte_length =
            usize::try_from(remaining.min(u64::try_from(chunk_byte_length).ok()?)).ok()?;
        Some(EvaluatorKeyStoreReadRequest {
            store_byte_offset: self.store_byte_offset.checked_add(local_byte_offset_u64)?,
            byte_length,
        })
    }

    fn absorb_next_chunk(
        &mut self,
        store_byte_offset: u64,
        chunk_bytes: &[u8],
        key_builder: &mut KeySwitchKeyNttBuilder,
        polynomial_pass: KeySwitchPolynomialPass,
    ) -> Result<(), RefusalReason> {
        let request = self
            .next_read_request()
            .ok_or(RefusalReason::ConsumedState)?;
        if request.store_byte_offset != store_byte_offset
            || request.byte_length != chunk_bytes.len()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.readback
            .as_mut()
            .ok_or(RefusalReason::ConsumedState)?
            .authenticate_chunk(self.next_chunk_index, chunk_bytes)?;
        self.decoder
            .absorb_bytes(chunk_bytes, |_, coefficients| match polynomial_pass {
                KeySwitchPolynomialPass::Runtime => key_builder
                    .absorb_runtime_limb(coefficients)
                    .map_err(canonical_replay_refusal),
                KeySwitchPolynomialPass::Auxiliary => key_builder
                    .absorb_auxiliary_limb(coefficients)
                    .map_err(canonical_replay_refusal),
            })?;
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        Ok(())
    }

    fn is_complete(&self) -> bool {
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        self.next_chunk_index
            .checked_mul(chunk_byte_length)
            .and_then(|observed| u64::try_from(observed).ok())
            .is_some_and(|observed| observed >= self.total_byte_length)
    }

    fn finish(mut self) -> Result<(), RefusalReason> {
        if !self.is_complete() {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        self.decoder.finish()?;
        self.readback
            .take()
            .ok_or(RefusalReason::ConsumedState)?
            .finish()
            .into_result()
            .map(|_| ())
    }
}

struct KeySwitchComponentByteDecoder {
    topology: KeySwitchComponentMaterialTopology,
    next_block_index: usize,
    next_limb_index: usize,
    pending_residue_bytes: [u8; size_of::<u64>()],
    pending_residue_byte_count: usize,
    current_limb: Vec<u64>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecoderDropObservation {
    retained_coefficient_count_before_drop: usize,
    pending_residue_byte_count_before_drop: usize,
    catalog_modulus_count_before_drop: usize,
    all_owned_buffers_cleared_before_release: bool,
}

#[cfg(test)]
thread_local! {
    static DECODER_DROP_OBSERVATIONS: std::cell::RefCell<Vec<DecoderDropObservation>> = const {
        std::cell::RefCell::new(Vec::new())
    };
}

#[cfg(test)]
fn clear_decoder_drop_observations() {
    DECODER_DROP_OBSERVATIONS.with(|observations| observations.borrow_mut().clear());
}

#[cfg(test)]
fn take_decoder_drop_observations() -> Vec<DecoderDropObservation> {
    DECODER_DROP_OBSERVATIONS.with(|observations| core::mem::take(&mut *observations.borrow_mut()))
}

impl Zeroize for KeySwitchComponentByteDecoder {
    fn zeroize(&mut self) {
        self.topology.zeroize();
        self.next_block_index.zeroize();
        self.next_limb_index.zeroize();
        self.pending_residue_bytes.zeroize();
        self.pending_residue_byte_count.zeroize();
        self.current_limb.zeroize();
    }
}

impl Drop for KeySwitchComponentByteDecoder {
    fn drop(&mut self) {
        #[cfg(test)]
        let observation = DecoderDropObservation {
            retained_coefficient_count_before_drop: self.current_limb.len(),
            pending_residue_byte_count_before_drop: self.pending_residue_byte_count,
            catalog_modulus_count_before_drop: self.topology.ordered_moduli().len(),
            all_owned_buffers_cleared_before_release: false,
        };
        self.zeroize();
        #[cfg(test)]
        DECODER_DROP_OBSERVATIONS.with(|observations| {
            observations.borrow_mut().push(DecoderDropObservation {
                all_owned_buffers_cleared_before_release: self.current_limb.is_empty()
                    && self.pending_residue_bytes == [0; size_of::<u64>()]
                    && self.pending_residue_byte_count == 0
                    && self.topology.owned_catalog_buffers_are_zeroized(),
                ..observation
            });
        });
    }
}

impl KeySwitchComponentByteDecoder {
    fn new(topology: KeySwitchComponentMaterialTopology) -> Result<Self, RefusalReason> {
        if topology.polynomial_degree() == 0
            || topology.data_block_count() == 0
            || topology.ordered_moduli().is_empty()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(Self {
            current_limb: Vec::with_capacity(topology.polynomial_degree()),
            topology,
            next_block_index: 0,
            next_limb_index: 0,
            pending_residue_bytes: [0; size_of::<u64>()],
            pending_residue_byte_count: 0,
        })
    }

    fn absorb_bytes(
        &mut self,
        mut bytes: &[u8],
        mut absorb_limb: impl FnMut(KeySwitchReplayLimbPosition, Vec<u64>) -> Result<(), RefusalReason>,
    ) -> Result<(), RefusalReason> {
        while !bytes.is_empty() {
            let position = self.next_limb_position()?;
            let residue_byte_length = canonical_residue_byte_length(position.modulus())
                .map_err(|_| RefusalReason::UnsupportedVersionOrSuite)?;
            let needed = residue_byte_length
                .checked_sub(self.pending_residue_byte_count)
                .ok_or(RefusalReason::WrongTypeOrLength)?;
            let copied = needed.min(bytes.len());
            self.pending_residue_bytes
                [self.pending_residue_byte_count..self.pending_residue_byte_count + copied]
                .copy_from_slice(&bytes[..copied]);
            self.pending_residue_byte_count += copied;
            bytes = &bytes[copied..];
            if self.pending_residue_byte_count != residue_byte_length {
                continue;
            }
            let residue = u64::from_le_bytes(self.pending_residue_bytes);
            self.pending_residue_bytes.fill(0);
            self.pending_residue_byte_count = 0;
            if residue >= position.modulus() {
                return Err(RefusalReason::MalformedEncoding);
            }
            self.current_limb.push(residue);
            if self.current_limb.len() == self.topology.polynomial_degree() {
                let mut completed_limb = Vec::with_capacity(self.topology.polynomial_degree());
                core::mem::swap(&mut completed_limb, &mut self.current_limb);
                absorb_limb(position, completed_limb)?;
                self.advance_limb()?;
            }
        }
        Ok(())
    }

    fn next_limb_position(&self) -> Result<KeySwitchReplayLimbPosition, RefusalReason> {
        let modulus = self
            .topology
            .ordered_moduli()
            .get(self.next_limb_index)
            .copied()
            .ok_or(RefusalReason::WrongTypeOrLength)?;
        Ok(KeySwitchReplayLimbPosition::from_topology_coordinate(
            self.next_block_index,
            self.next_limb_index,
            modulus,
        ))
    }

    fn advance_limb(&mut self) -> Result<(), RefusalReason> {
        self.next_limb_index = self
            .next_limb_index
            .checked_add(1)
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        if self.next_limb_index == self.topology.extended_limb_count() {
            self.next_limb_index = 0;
            self.next_block_index = self
                .next_block_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), RefusalReason> {
        if self.next_block_index != self.topology.data_block_count()
            || self.next_limb_index != 0
            || self.pending_residue_byte_count != 0
            || !self.current_limb.is_empty()
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
        Ok(())
    }
}

fn canonical_replay_refusal(error: CanonicalError) -> RefusalReason {
    match error.code {
        CanonicalErrorCode::MalformedLength | CanonicalErrorCode::ComponentMismatch => {
            RefusalReason::WrongTypeOrLength
        }
        CanonicalErrorCode::UnsupportedObjectVersion => RefusalReason::UnsupportedVersionOrSuite,
        CanonicalErrorCode::DuplicateField
        | CanonicalErrorCode::InvalidEnum
        | CanonicalErrorCode::InvalidProtocolObject
        | CanonicalErrorCode::InvalidHex
        | CanonicalErrorCode::InvalidUtf8
        | CanonicalErrorCode::MalformedMagic
        | CanonicalErrorCode::MalformedVarUint
        | CanonicalErrorCode::NonCanonicalVarUint
        | CanonicalErrorCode::TrailingBytes => RefusalReason::MalformedEncoding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::selected_evaluator_relinearization_entry_positions;

    fn test_topology() -> KeySwitchComponentMaterialTopology {
        KeySwitchComponentMaterialTopology::for_test_suite(&[257, 769], &[12_289], 1, 8)
            .expect("test replay topology")
    }

    fn test_component_bytes() -> Vec<u8> {
        let topology = test_topology();
        let mut bytes = Vec::new();
        for block_index in 0..topology.data_block_count() {
            for modulus in topology.ordered_moduli() {
                let residue_byte_length =
                    canonical_residue_byte_length(*modulus).expect("residue width");
                for coefficient_index in 0..topology.polynomial_degree() {
                    let residue = u64::try_from(
                        block_index * 31 + coefficient_index * 7 + usize::from(*modulus == 769),
                    )
                    .expect("test residue fits")
                        % modulus;
                    bytes.extend_from_slice(&residue.to_le_bytes()[..residue_byte_length]);
                }
            }
        }
        bytes
    }

    #[test]
    fn resident_evaluator_key_guard_releases_ownership_on_drop() {
        let resident_key_active = Rc::new(Cell::new(false));
        let first_guard = ResidentEvaluatorKeyGuard::acquire(Rc::clone(&resident_key_active))
            .expect("the first resident evaluator key guard is available");
        assert!(resident_key_active.get());
        assert!(matches!(
            ResidentEvaluatorKeyGuard::acquire(Rc::clone(&resident_key_active)),
            Err(RefusalReason::ConsumedState)
        ));

        drop(first_guard);
        assert!(!resident_key_active.get());

        let reused_guard = ResidentEvaluatorKeyGuard::acquire(Rc::clone(&resident_key_active))
            .expect("the resident evaluator key guard is reusable after drop");
        assert!(resident_key_active.get());
        drop(reused_guard);
        assert!(!resident_key_active.get());
    }

    #[test]
    fn verified_context_drop_zeroizes_complete_key_before_guard_release() {
        clear_verified_context_drop_observations();
        let resident_key_active = Rc::new(Cell::new(false));
        let resident_key_guard =
            ResidentEvaluatorKeyGuard::acquire(Rc::clone(&resident_key_active))
                .expect("resident key guard");
        let position = selected_evaluator_relinearization_entry_positions()
            .expect("selected relinearization positions")
            .into_iter()
            .next()
            .expect("at least one selected relinearization position");
        let context = VerifiedEvaluatorKeyContext {
            evaluator_replay_context_hash: [0x5a; 64],
            _resident_key_guard: resident_key_guard,
            position,
            key: KeySwitchKey::from_zeroization_test_values(),
            ntt_transform_count: 7,
        };
        assert!(resident_key_active.get());

        drop(context);

        assert!(!resident_key_active.get());
        let observations = take_verified_context_drop_observations();
        assert_eq!(observations.len(), 1);
        assert!(observations[0].retained_word_count_before_drop >= 5);
        assert!(observations[0].catalog_word_count_before_drop > 1);
        assert!(observations[0].key_cleared_while_resident_guard_was_active);
    }

    #[test]
    fn component_decoder_streams_exact_block_limb_order_across_unaligned_chunks() {
        let topology = test_topology();
        let bytes = test_component_bytes();
        let mut decoder = KeySwitchComponentByteDecoder::new(topology.clone()).expect("decoder");
        let mut decoded = Vec::new();
        let mut byte_offset = 0;
        for chunk_length in [1, 7, 3, 19, 2, 11, 5, 23] {
            if byte_offset == bytes.len() {
                break;
            }
            let end = bytes.len().min(byte_offset + chunk_length);
            decoder
                .absorb_bytes(&bytes[byte_offset..end], |position, coefficients| {
                    decoded.push((position, coefficients));
                    Ok(())
                })
                .expect("unaligned replay chunk decodes");
            byte_offset = end;
        }
        if byte_offset < bytes.len() {
            decoder
                .absorb_bytes(&bytes[byte_offset..], |position, coefficients| {
                    decoded.push((position, coefficients));
                    Ok(())
                })
                .expect("remaining replay bytes decode");
        }
        decoder.finish().expect("complete component decode");
        assert_eq!(
            decoded.len(),
            topology.data_block_count() * topology.extended_limb_count()
        );
        for (ordinal, (position, coefficients)) in decoded.iter().enumerate() {
            assert_eq!(
                (position.block_index(), position.extended_limb_index()),
                (
                    ordinal / topology.extended_limb_count(),
                    ordinal % topology.extended_limb_count()
                )
            );
            assert_eq!(coefficients.len(), topology.polynomial_degree());
            assert!(
                coefficients
                    .iter()
                    .all(|coefficient| *coefficient < position.modulus())
            );
        }
    }

    #[test]
    fn component_decoder_rejects_noncanonical_residues_and_incomplete_limbs() {
        let topology = test_topology();
        let first_modulus = topology.ordered_moduli()[0];
        let residue_byte_length =
            canonical_residue_byte_length(first_modulus).expect("residue width");
        let encoded_modulus = first_modulus.to_le_bytes();
        let mut decoder = KeySwitchComponentByteDecoder::new(topology.clone()).expect("decoder");
        assert_eq!(
            decoder.absorb_bytes(&encoded_modulus[..residue_byte_length], |_, _| Ok(())),
            Err(RefusalReason::MalformedEncoding)
        );

        let mut incomplete =
            KeySwitchComponentByteDecoder::new(topology).expect("incomplete decoder");
        incomplete
            .absorb_bytes(&[1], |_, _| Ok(()))
            .expect("partial residue is retained");
        assert_eq!(incomplete.finish(), Err(RefusalReason::WrongTypeOrLength));
    }

    #[test]
    fn partial_decoder_drop_clears_unaligned_residue_limb_and_catalog_buffers() {
        clear_decoder_drop_observations();
        {
            let topology = test_topology();
            let bytes = test_component_bytes();
            let first_residue_byte_length =
                canonical_residue_byte_length(topology.ordered_moduli()[0])
                    .expect("first residue width");
            let mut decoder = KeySwitchComponentByteDecoder::new(topology).expect("decoder");
            decoder
                .absorb_bytes(&bytes[..first_residue_byte_length + 1], |_, _| {
                    panic!("one coefficient cannot complete an eight-coefficient limb")
                })
                .expect("one complete residue and one partial residue are retained");
        }

        let observations = take_decoder_drop_observations();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].retained_coefficient_count_before_drop, 1);
        assert_eq!(observations[0].pending_residue_byte_count_before_drop, 1);
        assert_eq!(observations[0].catalog_modulus_count_before_drop, 3);
        assert!(observations[0].all_owned_buffers_cleared_before_release);
    }
}
