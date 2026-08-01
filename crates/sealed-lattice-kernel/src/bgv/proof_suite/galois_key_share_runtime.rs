//! Browser/WASM runtime adapter for the suite-fixed Galois key-share family.
//!
//! Generation derives the exact `0x1217` statement and all source trees from
//! retained setup-generation authority. The caller supplies only existing
//! reset-safe ceremony capabilities and an authenticated checkpoint lineage.

use core::slice;
use std::cell::RefCell;

use crate::{
    bgv::setup::{
        SetupGaloisGenerationPreparationError, SetupGeneratedGaloisSourceAuthority,
        SetupGenerationAuthorityHandle, SetupGenerationGaloisApplication,
        SetupGenerationGaloisPreparationSource,
        add_generated_proof_source_to_accepted_setup_package_builder,
        commit_prepackage_galois_source, commit_prepackage_generated_galois_source,
        preflight_prepackage_galois_source_slot, preflight_prepackage_generated_galois_source_slot,
        resolve_setup_generation_galois_preparation_source,
        restore_prepackage_galois_statement_source, take_prepackage_galois_statement_source,
        with_prepackage_generated_galois_source, with_prepackage_relinearization_source,
        with_setup_generation_galois_batch, with_setup_generation_galois_public_component_chunk,
    },
    foundation::{
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, CanonicalDecodeLimits,
        CanonicalStreamReadbackVerifier, FOUNDATION_PROFILE, FoundationObjectType,
        FoundationSchemaError, Hash512, ParticipantIdentity, PreparedActionProofAttemptSource,
        ProofApplicationSlot, ProofApplicationSlotCeilings, RefusalReason,
        STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, StreamDescriptor,
        VerifiedBoardApplicationSource, VerifiedStateReservationRuntimeBinding,
        resolve_prepared_action_proof_attempt_source, resolve_verified_board_application_sources,
        verified_state_reservation_binding,
    },
};

use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    cancel_common_proof_verification_family_adapter_reservation,
    commit_reserved_common_proof_verification_family_adapter_from_upstream,
    preflight_reserved_common_proof_verification_family_adapter_from_upstream,
    reserve_common_proof_verification_family_adapter,
    retain_common_proof_generation_family_adapter, with_common_proof_selected_suite,
};
use super::{
    CommonProofGenerationPreparationError, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofSelectedSuiteCapabilityHandle, ComponentMaterialOwnershipBinding,
    KeySwitchComponentMaterialTopology, KeySwitchComponentPublicPolynomialStream,
    PreparedCommonProofGeneration, ProofProfileError, RecomputedKeySwitchComponentTree,
    RelationPlanError, SelectedApplicationStatementContext, SelectedEvaluatorEntryKind,
    SelectedProofAccountingError, SetupPublicPolynomialContext, SetupPublicPolynomialRootRole,
    SetupPublicPolynomialTree, VerifiedCommonProofCapabilityHandle,
    VerifiedCommonProofStatementSource, VerifiedEvaluatorAuxiliaryRoot,
    VerifiedGaloisSourceMaterialBatchPreflight, VerifiedKeySwitchComponentMaterial,
    VerifiedStatementOwnedTree, compile_galois_key_share_relation_with_source_layout,
    decode_selected_galois_key_share_statement, selected_evaluator_galois_entry_positions,
    selected_galois_key_share_relation_plan_input, selected_proof_runtime_limits,
    selected_relation_plan_check_context, verified_application_statement_hash,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION: u32 = 0;

fn component_runtime_error(
    error: super::ComponentPublicPolynomialRuntimeError,
) -> CommonProofRuntimeError {
    match error {
        super::ComponentPublicPolynomialRuntimeError::Refusal(RefusalReason::ConsumedState) => {
            CommonProofRuntimeError::WrongOperationPhase
        }
        super::ComponentPublicPolynomialRuntimeError::Refusal(
            RefusalReason::OutsideSupportedProfile,
        ) => CommonProofRuntimeError::AllocationLimitExceeded,
        super::ComponentPublicPolynomialRuntimeError::Refusal(_)
        | super::ComponentPublicPolynomialRuntimeError::PublicPolynomial(_) => {
            CommonProofRuntimeError::WrongVerificationBinding
        }
    }
}

#[derive(Debug)]
enum GaloisKeyShareRuntimeError {
    Accounting(SelectedProofAccountingError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    Runtime(CommonProofRuntimeError),
    GenerationPreparation(SetupGaloisGenerationPreparationError),
    Foundation(FoundationSchemaError),
    ActionRandomnessRuntime(u32),
    BoardRuntime(u32),
    StateRuntime(u32),
    Refusal(RefusalReason),
    InvalidInput,
}

impl From<SelectedProofAccountingError> for GaloisKeyShareRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<ProofProfileError> for GaloisKeyShareRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for GaloisKeyShareRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for GaloisKeyShareRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofRuntimeError> for GaloisKeyShareRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<SetupGaloisGenerationPreparationError> for GaloisKeyShareRuntimeError {
    fn from(error: SetupGaloisGenerationPreparationError) -> Self {
        Self::GenerationPreparation(error)
    }
}

impl From<FoundationSchemaError> for GaloisKeyShareRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

impl From<RefusalReason> for GaloisKeyShareRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

struct SingleActiveGaloisGenerationSourceRegistry {
    active: Option<(u32, PendingGeneratedGaloisSource)>,
    next_handle: u32,
}

impl Default for SingleActiveGaloisGenerationSourceRegistry {
    fn default() -> Self {
        Self {
            active: None,
            next_handle: 1,
        }
    }
}

impl SingleActiveGaloisGenerationSourceRegistry {
    fn retain(
        &mut self,
        source: PendingGeneratedGaloisSource,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.active.is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        if handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.active = Some((handle, source));
        Ok(handle)
    }

    fn source(
        &self,
        handle: u32,
    ) -> Result<&PendingGeneratedGaloisSource, CommonProofRuntimeError> {
        self.active
            .as_ref()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn source_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut PendingGeneratedGaloisSource, CommonProofRuntimeError> {
        self.active
            .as_mut()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<PendingGeneratedGaloisSource, CommonProofRuntimeError> {
        self.source(handle)?;
        self.active
            .take()
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(
        &mut self,
        handle: u32,
        source: PendingGeneratedGaloisSource,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.active.is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.active = Some((handle, source));
        Ok(())
    }
}

pub(crate) struct PendingGeneratedGaloisSource {
    setup_generation_authority_identifier: u32,
    // Retains the consumed generation capability until the pending source is
    // committed or discarded.
    _retained_preparation_source: SetupGenerationGaloisPreparationSource,
    generated_source_authority: SetupGeneratedGaloisSourceAuthority,
    component_readback_lifecycle: GaloisComponentReadbackLifecycle,
}

impl PendingGeneratedGaloisSource {
    pub(crate) const fn generated_source_authority(&self) -> &SetupGeneratedGaloisSourceAuthority {
        &self.generated_source_authority
    }

    const fn setup_generation_authority_handle(&self) -> SetupGenerationAuthorityHandle {
        SetupGenerationAuthorityHandle::from_identifier(self.setup_generation_authority_identifier)
    }

    fn require_completed_component_readback(&self) -> Result<(), CommonProofRuntimeError> {
        if self.component_readback_lifecycle == GaloisComponentReadbackLifecycle::Completed {
            Ok(())
        } else {
            Err(CommonProofRuntimeError::WrongOperationPhase)
        }
    }

    pub(crate) fn into_generated_source_authority(self) -> SetupGeneratedGaloisSourceAuthority {
        self.generated_source_authority
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GaloisComponentReadbackLifecycle {
    Available,
    Active(u32),
    Completed,
    Cancelled,
}

struct GaloisGeneratedComponentReadbackBinding {
    material_root: [u8; Hash512::BYTE_LENGTH],
    stream_descriptor: StreamDescriptor,
    encoded_stream_descriptor: Box<[u8]>,
    authenticated_readback: Option<CanonicalStreamReadbackVerifier>,
}

struct GaloisGeneratedComponentReadback {
    owner_generation_source_handle: u32,
    setup_generation_authority_handle: SetupGenerationAuthorityHandle,
    ordered_components: Box<[GaloisGeneratedComponentReadbackBinding]>,
    next_component_ordinal: usize,
    next_chunk_index: usize,
}

impl GaloisGeneratedComponentReadback {
    fn from_pending_source(
        owner_generation_source_handle: u32,
        pending_source: &PendingGeneratedGaloisSource,
    ) -> Result<Self, GaloisKeyShareRuntimeError> {
        let selected_positions = selected_evaluator_galois_entry_positions().map_err(|_| {
            GaloisKeyShareRuntimeError::Runtime(CommonProofRuntimeError::WrongVerificationBinding)
        })?;
        let generated_components = pending_source
            .generated_source_authority()
            .ordered_components();
        if generated_components.len() != selected_positions.len() {
            return Err(GaloisKeyShareRuntimeError::Runtime(
                CommonProofRuntimeError::WrongVerificationBinding,
            ));
        }
        let mut ordered_components = Vec::with_capacity(generated_components.len());
        for (generated_component, expected_position) in
            generated_components.iter().zip(selected_positions)
        {
            if generated_component.evaluator_position() != expected_position {
                return Err(GaloisKeyShareRuntimeError::Runtime(
                    CommonProofRuntimeError::WrongVerificationBinding,
                ));
            }
            let stream_descriptor = generated_component.stream_descriptor().clone();
            let encoded_stream_descriptor = stream_descriptor.encode()?.into_boxed_slice();
            let authenticated_readback = generated_component.begin_authenticated_readback()?;
            ordered_components.push(GaloisGeneratedComponentReadbackBinding {
                material_root: generated_component.material_root().into_bytes(),
                stream_descriptor,
                encoded_stream_descriptor,
                authenticated_readback: Some(authenticated_readback),
            });
        }
        Ok(Self {
            owner_generation_source_handle,
            setup_generation_authority_handle: pending_source.setup_generation_authority_handle(),
            ordered_components: ordered_components.into_boxed_slice(),
            next_component_ordinal: 0,
            next_chunk_index: 0,
        })
    }

    const fn owner_generation_source_handle(&self) -> u32 {
        self.owner_generation_source_handle
    }

    fn component_count(&self) -> usize {
        self.ordered_components.len()
    }

    fn current_component(
        &self,
        component_ordinal: usize,
    ) -> Result<&GaloisGeneratedComponentReadbackBinding, CommonProofRuntimeError> {
        if component_ordinal != self.next_component_ordinal {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.ordered_components
            .get(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn current_component_mut(
        &mut self,
        component_ordinal: usize,
    ) -> Result<&mut GaloisGeneratedComponentReadbackBinding, CommonProofRuntimeError> {
        if component_ordinal != self.next_component_ordinal {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.ordered_components
            .get_mut(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)
    }

    fn expected_chunk_byte_length(
        &self,
        component_ordinal: usize,
        chunk_index: usize,
    ) -> Result<usize, GaloisKeyShareRuntimeError> {
        if chunk_index != self.next_chunk_index {
            return Err(GaloisKeyShareRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        let component = self.current_component(component_ordinal)?;
        if chunk_index >= component.stream_descriptor.ordered_chunk_digests.len() {
            return Err(GaloisKeyShareRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let byte_start = chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(GaloisKeyShareRuntimeError::InvalidInput)?;
        let total_byte_length = usize::try_from(component.stream_descriptor.total_byte_length)
            .map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)?;
        Ok(total_byte_length
            .checked_sub(byte_start)
            .ok_or(GaloisKeyShareRuntimeError::InvalidInput)?
            .min(chunk_byte_length))
    }

    fn authenticate_and_copy_chunk(
        &mut self,
        component_ordinal: usize,
        chunk_index: usize,
        source_chunk: &[u8],
        output: &mut [u8],
    ) -> Result<(), GaloisKeyShareRuntimeError> {
        let expected_byte_length =
            self.expected_chunk_byte_length(component_ordinal, chunk_index)?;
        if source_chunk.len() != expected_byte_length || output.len() != expected_byte_length {
            return Err(GaloisKeyShareRuntimeError::InvalidInput);
        }
        let is_final_component_chunk = {
            let component = self.current_component_mut(component_ordinal)?;
            let readback = component.authenticated_readback.as_mut().ok_or(
                GaloisKeyShareRuntimeError::Runtime(CommonProofRuntimeError::WrongOperationPhase),
            )?;
            readback.authenticate_chunk(chunk_index, source_chunk)?;
            output.copy_from_slice(source_chunk);
            chunk_index + 1 == component.stream_descriptor.ordered_chunk_digests.len()
        };
        self.next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(GaloisKeyShareRuntimeError::InvalidInput)?;
        if is_final_component_chunk {
            let completed_readback = self
                .current_component_mut(component_ordinal)?
                .authenticated_readback
                .take()
                .ok_or(GaloisKeyShareRuntimeError::Runtime(
                    CommonProofRuntimeError::WrongOperationPhase,
                ))?;
            completed_readback.finish().into_result()?;
            self.next_component_ordinal = self
                .next_component_ordinal
                .checked_add(1)
                .ok_or(GaloisKeyShareRuntimeError::InvalidInput)?;
            self.next_chunk_index = 0;
        }
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.next_component_ordinal == self.ordered_components.len()
            && self.next_chunk_index == 0
            && self
                .ordered_components
                .iter()
                .all(|component| component.authenticated_readback.is_none())
    }
}

struct SingleActiveGaloisComponentReadbackRegistry {
    active: Option<(u32, GaloisGeneratedComponentReadback)>,
    next_handle: u32,
}

impl Default for SingleActiveGaloisComponentReadbackRegistry {
    fn default() -> Self {
        Self {
            active: None,
            next_handle: 1,
        }
    }
}

impl SingleActiveGaloisComponentReadbackRegistry {
    fn retain(
        &mut self,
        readback: GaloisGeneratedComponentReadback,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.active.is_some() || self.next_handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.active = Some((handle, readback));
        Ok(handle)
    }

    fn entry(
        &self,
        handle: u32,
    ) -> Result<&GaloisGeneratedComponentReadback, CommonProofRuntimeError> {
        self.active
            .as_ref()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, readback)| readback)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn entry_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut GaloisGeneratedComponentReadback, CommonProofRuntimeError> {
        self.active
            .as_mut()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, readback)| readback)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn finish(
        &mut self,
        handle: u32,
        owner_generation_source_handle: u32,
    ) -> Result<(), CommonProofRuntimeError> {
        let entry = self.entry(handle)?;
        if entry.owner_generation_source_handle() != owner_generation_source_handle
            || !entry.is_complete()
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.active = None;
        Ok(())
    }

    fn cancel(
        &mut self,
        handle: u32,
        owner_generation_source_handle: u32,
    ) -> Result<(), CommonProofRuntimeError> {
        let entry = self.entry(handle)?;
        if entry.owner_generation_source_handle() != owner_generation_source_handle {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.active = None;
        Ok(())
    }
}

thread_local! {
    static GALOIS_GENERATION_SOURCE_REGISTRY:
        RefCell<SingleActiveGaloisGenerationSourceRegistry> =
        RefCell::new(SingleActiveGaloisGenerationSourceRegistry::default());
    static GALOIS_COMPONENT_READBACK_REGISTRY:
        RefCell<SingleActiveGaloisComponentReadbackRegistry> =
        RefCell::new(SingleActiveGaloisComponentReadbackRegistry::default());
}

struct GaloisVerificationComponentIngress {
    topology: KeySwitchComponentMaterialTopology,
    context: SetupPublicPolynomialContext,
    expected_contribution_root: [u8; Hash512::BYTE_LENGTH],
    application_owned_tree: Option<RecomputedKeySwitchComponentTree>,
}

struct ActiveGaloisComponentIngress {
    component_ordinal: usize,
    stream: KeySwitchComponentPublicPolynomialStream,
}

struct GaloisVerificationIngress {
    prepackage_catalog_handle: u32,
    roster_position: u16,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_source: Option<VerifiedCommonProofStatementSource>,
    ordered_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    ordered_components: Vec<GaloisVerificationComponentIngress>,
    next_component_ordinal: usize,
    active_ingress: Option<ActiveGaloisComponentIngress>,
}

impl GaloisVerificationIngress {
    fn begin_component(
        &mut self,
        component_ordinal: usize,
        stream_descriptor: StreamDescriptor,
        ownership_binding: ComponentMaterialOwnershipBinding,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.active_ingress.is_some() || component_ordinal != self.next_component_ordinal {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let component = self
            .ordered_components
            .get(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        if component.application_owned_tree.is_some() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let stream = KeySwitchComponentPublicPolynomialStream::begin(
            component.topology.clone(),
            ownership_binding,
            stream_descriptor,
        )
        .map_err(component_runtime_error)?;
        self.active_ingress = Some(ActiveGaloisComponentIngress {
            component_ordinal,
            stream,
        });
        Ok(())
    }

    fn absorb_active_chunk(
        &mut self,
        component_ordinal: usize,
        chunk_index: usize,
        chunk_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let active_ingress = self
            .active_ingress
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let ActiveGaloisComponentIngress {
            component_ordinal: active_component_ordinal,
            mut stream,
        } = active_ingress;
        if active_component_ordinal != component_ordinal {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        match stream.absorb_chunk(chunk_index, chunk_bytes) {
            Ok(()) => {
                self.active_ingress = Some(ActiveGaloisComponentIngress {
                    component_ordinal,
                    stream,
                });
                Ok(())
            }
            Err(error) => Err(component_runtime_error(error)),
        }
    }

    fn finish_component(
        &mut self,
        component_ordinal: usize,
    ) -> Result<(), CommonProofRuntimeError> {
        let active_ingress = self
            .active_ingress
            .take()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let ActiveGaloisComponentIngress {
            component_ordinal: active_component_ordinal,
            stream,
        } = active_ingress;
        if active_component_ordinal != component_ordinal
            || component_ordinal != self.next_component_ordinal
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let component = self
            .ordered_components
            .get_mut(component_ordinal)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let recomputed = stream
            .finish(component.context.clone())
            .map_err(component_runtime_error)?;
        if recomputed.tree().root() != component.expected_contribution_root {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        component.application_owned_tree = Some(recomputed);
        self.next_component_ordinal = self
            .next_component_ordinal
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        Ok(())
    }

    fn is_complete(&self) -> bool {
        self.active_ingress.is_none()
            && self.next_component_ordinal == self.ordered_components.len()
            && self
                .ordered_components
                .iter()
                .all(|component| component.application_owned_tree.is_some())
    }
}

struct SingleActiveGaloisVerificationRegistry<Source> {
    active: Option<(u32, Source)>,
    reservation: Option<u32>,
    next_handle: u32,
}

impl<Source> Default for SingleActiveGaloisVerificationRegistry<Source> {
    fn default() -> Self {
        Self {
            active: None,
            reservation: None,
            next_handle: 1,
        }
    }
}

impl<Source> SingleActiveGaloisVerificationRegistry<Source> {
    fn require_capacity(&self) -> Result<(), CommonProofRuntimeError> {
        if self.active.is_some() || self.reservation.is_some() || self.next_handle == 0 {
            Err(CommonProofRuntimeError::AllocationLimitExceeded)
        } else {
            Ok(())
        }
    }

    fn retain_recovering(
        &mut self,
        source: Source,
    ) -> Result<u32, (CommonProofRuntimeError, Source)> {
        if let Err(error) = self.require_capacity() {
            return Err((error, source));
        }
        let handle = self.next_handle;
        let Some(next_handle) = handle.checked_add(1).filter(|next| *next != 0) else {
            return Err((CommonProofRuntimeError::AllocationLimitExceeded, source));
        };
        self.next_handle = next_handle;
        self.active = Some((handle, source));
        Ok(handle)
    }

    fn reserve(&mut self) -> Result<u32, CommonProofRuntimeError> {
        self.require_capacity()?;
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.reservation = Some(handle);
        Ok(handle)
    }

    fn commit_reserved(&mut self, handle: u32, source: Source) {
        assert_eq!(
            self.reservation.take(),
            Some(handle),
            "reserved Galois verifier destination remains live during commit"
        );
        assert!(
            self.active.replace((handle, source)).is_none(),
            "reserved Galois verifier destination is unique"
        );
    }

    fn cancel_reservation(&mut self, handle: u32) -> Result<(), CommonProofRuntimeError> {
        if self.reservation == Some(handle) {
            self.reservation = None;
            Ok(())
        } else {
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        }
    }

    fn with_mut<Output>(
        &mut self,
        handle: u32,
        inspect: impl FnOnce(&mut Source) -> Result<Output, CommonProofRuntimeError>,
    ) -> Result<Output, CommonProofRuntimeError> {
        let source = self
            .active
            .as_mut()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        inspect(source)
    }

    fn take(&mut self, handle: u32) -> Result<Source, CommonProofRuntimeError> {
        self.with_mut(handle, |_| Ok(()))?;
        self.active
            .take()
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(&mut self, handle: u32, source: Source) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.active.is_some() || self.reservation.is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.active = Some((handle, source));
        Ok(())
    }
}

struct GaloisVerificationTerminalSource {
    prepackage_catalog_handle: u32,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    canonical_application_statement_bytes: Vec<u8>,
    statement_trees: Vec<VerifiedStatementOwnedTree>,
    ordered_auxiliary_roots: Vec<VerifiedEvaluatorAuxiliaryRoot>,
    ordered_contribution_trees: Vec<SetupPublicPolynomialTree>,
    ordered_materials: Vec<VerifiedKeySwitchComponentMaterial>,
}

thread_local! {
    static GALOIS_VERIFICATION_INGRESS_REGISTRY:
        RefCell<SingleActiveGaloisVerificationRegistry<GaloisVerificationIngress>> =
        RefCell::new(SingleActiveGaloisVerificationRegistry::default());
    static GALOIS_VERIFICATION_TERMINAL_SOURCE_REGISTRY:
        RefCell<SingleActiveGaloisVerificationRegistry<GaloisVerificationTerminalSource>> =
        RefCell::new(SingleActiveGaloisVerificationRegistry::default());
}

pub(crate) fn take_pending_generated_galois_source(
    handle: u32,
) -> Result<PendingGeneratedGaloisSource, CommonProofRuntimeError> {
    GALOIS_GENERATION_SOURCE_REGISTRY.with(|registry| registry.borrow_mut().take(handle))
}

pub(crate) fn restore_pending_generated_galois_source(
    handle: u32,
    source: PendingGeneratedGaloisSource,
) -> Result<(), CommonProofRuntimeError> {
    GALOIS_GENERATION_SOURCE_REGISTRY.with(|registry| registry.borrow_mut().restore(handle, source))
}

struct SelectedGaloisProofRuntimePlan {
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
}

fn selected_galois_proof_runtime_plan(
    canonical_application_statement_bytes: &[u8],
    batch_schedule_position: u32,
) -> Result<SelectedGaloisProofRuntimePlan, GaloisKeyShareRuntimeError> {
    let statement_schema_identifier =
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or(GaloisKeyShareRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))?;
    let input = selected_galois_key_share_relation_plan_input()?;
    let compiled_relation =
        compile_galois_key_share_relation_with_source_layout(&input, &relation_context)?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &compiled_relation.relation_plan,
        &relation_context,
        Some(batch_schedule_position),
        None,
    )?;
    let limits =
        selected_proof_runtime_limits(canonical_application_statement_bytes, &relation_plan)?;
    Ok(SelectedGaloisProofRuntimePlan {
        relation_plan,
        limits,
    })
}

fn require_selected_suite_matches_generation_source(
    selected_suite_handle: u32,
    source: &SetupGenerationGaloisPreparationSource,
) -> Result<(), GaloisKeyShareRuntimeError> {
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() != source.protocol_version()
            || selected_suite.suite_identifier() != source.suite_identifier()
        {
            return Err(GaloisKeyShareRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(GaloisKeyShareRuntimeError::Runtime)??;
    Ok(())
}

fn resolve_single_setup_intent_source(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
) -> Result<VerifiedBoardApplicationSource, GaloisKeyShareRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(GaloisKeyShareRuntimeError::InvalidInput);
    }
    let mut sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[setup_intent_object_handle],
    )
    .map_err(GaloisKeyShareRuntimeError::BoardRuntime)?;
    let source = sources.pop().ok_or(GaloisKeyShareRuntimeError::Refusal(
        RefusalReason::MissingPrerequisite,
    ))?;
    if !sources.is_empty() {
        return Err(GaloisKeyShareRuntimeError::InvalidInput);
    }
    source.setup_intent_payload()?;
    Ok(source)
}

fn require_setup_intent_matches_generation_source(
    board_source: &VerifiedBoardApplicationSource,
    source: &SetupGenerationGaloisPreparationSource,
) -> Result<(), GaloisKeyShareRuntimeError> {
    if board_source.object_type() != FoundationObjectType::SetupIntent
        || board_source.suite_identifier().into_bytes() != source.suite_identifier()
        || board_source.manifest_hash().into_bytes() != source.manifest_hash()
        || board_source.ceremony_context_hash().into_bytes() != source.ceremony_context_hash()
        || board_source.action_context_hash().into_bytes() != source.action_context_hash()
        || board_source.roster_hash().into_bytes() != source.roster_hash()
        || board_source.object_hash().into_bytes() != source.source_setup_intent_object_hash()
        || board_source.producer_sequence() != 0
        || board_source.producer_roster_position() != Some(source.roster_position())
        || board_source
            .producer_participant_identity()
            .map(ParticipantIdentity::into_bytes)
            != Some(source.participant_identity())
    {
        return Err(GaloisKeyShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_generation_reservation_binding(
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    source: &SetupGenerationGaloisPreparationSource,
) -> Result<VerifiedStateReservationRuntimeBinding, GaloisKeyShareRuntimeError> {
    if state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(GaloisKeyShareRuntimeError::InvalidInput);
    }
    let binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(GaloisKeyShareRuntimeError::StateRuntime)?;
    if binding.authorization_hash.into_bytes() != source.action_randomness_authorization_hash() {
        return Err(GaloisKeyShareRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    Ok(binding)
}

fn resolve_galois_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    board_source: &VerifiedBoardApplicationSource,
    source: &SetupGenerationGaloisPreparationSource,
    checkpoint_continuation: crate::foundation::AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedActionProofAttemptSource, GaloisKeyShareRuntimeError> {
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(source.suite_identifier()),
        Hash512::from_bytes(source.ceremony_context_hash()),
        Hash512::from_bytes(source.action_context_hash()),
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(source.roster_position()),
        Some(source.batch_schedule_position()),
        None,
    )?;
    let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        source.protocol_version(),
        source.suite_identifier(),
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        source.canonical_application_statement_bytes(),
    ));
    resolve_prepared_action_proof_attempt_source(
        action_randomness_handle,
        verified_reservation_binding,
        board_source,
        application_slot,
        application_statement_hash,
        checkpoint_continuation,
    )
    .map_err(GaloisKeyShareRuntimeError::ActionRandomnessRuntime)
}

fn prepare_galois_common_generation(
    setup_generation_authority_handle: u32,
    preparation_source: &SetupGenerationGaloisPreparationSource,
    prepared_attempt: PreparedActionProofAttemptSource,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
) -> Result<
    (
        PreparedCommonProofGeneration,
        SetupGeneratedGaloisSourceAuthority,
    ),
    GaloisKeyShareRuntimeError,
> {
    let statement = decode_selected_galois_key_share_statement(
        preparation_source.canonical_application_statement_bytes(),
        SelectedApplicationStatementContext::new(
            preparation_source.protocol_version(),
            preparation_source.suite_identifier(),
            Some(preparation_source.batch_schedule_position()),
            None,
        ),
    )
    .map_err(|_| GaloisKeyShareRuntimeError::Refusal(RefusalReason::WrongContext))?;
    if statement.setup_proof_context_hash() != preparation_source.setup_proof_context_hash() {
        return Err(GaloisKeyShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    let application = SetupGenerationGaloisApplication::from_decoded_statement(
        prepared_attempt,
        preparation_source.canonical_application_statement_bytes(),
        statement.setup_proof_context_hash(),
        preparation_source.roster_hash(),
        statement.participant_identity(),
        statement.roster_position(),
        statement.batch_schedule_position(),
    );
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    with_setup_generation_galois_batch(&authority_handle, &application, |source| {
        let generated_source_authority = source.generated_source_authority()?;
        let prepared_generation = source.prepare_common_generation(relation_plan, limits)?;
        Ok((prepared_generation, generated_source_authority))
    })
    .map_err(GaloisKeyShareRuntimeError::GenerationPreparation)
}

fn resumed_generation_preparation_error(
    error: GaloisKeyShareRuntimeError,
) -> CommonProofGenerationPreparationError {
    match error {
        GaloisKeyShareRuntimeError::Runtime(error) => {
            CommonProofGenerationPreparationError::Runtime(error)
        }
        GaloisKeyShareRuntimeError::GenerationPreparation(
            SetupGaloisGenerationPreparationError::Runtime(error),
        ) => CommonProofGenerationPreparationError::Runtime(error),
        GaloisKeyShareRuntimeError::GenerationPreparation(
            SetupGaloisGenerationPreparationError::Preparation(error),
        ) => error,
        GaloisKeyShareRuntimeError::GenerationPreparation(
            SetupGaloisGenerationPreparationError::Refusal(RefusalReason::ConsumedState),
        ) => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::UnknownOrStaleHandle,
        ),
        _ => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding,
        ),
    }
}

#[derive(Clone, Copy)]
enum GaloisGenerationMode {
    Fresh,
    Resume,
}

#[allow(clippy::too_many_arguments)]
fn prepare_galois_generation(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: GaloisGenerationMode,
) -> Result<(u32, u32), GaloisKeyShareRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        return Err(GaloisKeyShareRuntimeError::InvalidInput);
    }
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    let preparation_source = resolve_setup_generation_galois_preparation_source(&authority_handle)?;
    require_selected_suite_matches_generation_source(selected_suite_handle, &preparation_source)?;
    let board_source = resolve_single_setup_intent_source(
        board_verifier_session_handle,
        board_verifier_session_capability,
        setup_intent_object_handle,
    )?;
    require_setup_intent_matches_generation_source(&board_source, &preparation_source)?;
    let verified_reservation_binding = resolve_generation_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
        &preparation_source,
    )?;
    let runtime_plan = selected_galois_proof_runtime_plan(
        preparation_source.canonical_application_statement_bytes(),
        preparation_source.batch_schedule_position(),
    )?;
    let checkpoint_schedule_digest = runtime_plan.relation_plan.checkpoint_schedule_digest()?;
    let fresh_continuation =
        crate::foundation::AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let fresh_prepared_attempt = resolve_galois_prepared_attempt(
        action_randomness_handle,
        verified_reservation_binding,
        &board_source,
        &preparation_source,
        fresh_continuation,
    )?;
    let (generation_family_adapter, generated_source_authority) = match generation_mode {
        GaloisGenerationMode::Fresh => {
            let (prepared_generation, generated_source_authority) =
                prepare_galois_common_generation(
                    setup_generation_authority_handle,
                    &preparation_source,
                    fresh_prepared_attempt,
                    runtime_plan.relation_plan,
                    runtime_plan.limits,
                )?;
            (
                CommonProofGenerationFamilyAdapter::fresh(prepared_generation),
                generated_source_authority,
            )
        }
        GaloisGenerationMode::Resume => {
            let (fresh_preparation, generated_source_authority) = prepare_galois_common_generation(
                setup_generation_authority_handle,
                &preparation_source,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
                fresh_preparation.application_statement_schema_identifier(),
                fresh_preparation.runtime_binding_hash(),
                fresh_preparation.generation_authorization_hash(),
                fresh_preparation.proof_attempt_lineage_identifier(),
            );
            drop(fresh_preparation);
            let resumed_preparation_source = preparation_source.clone();
            let adapter = CommonProofGenerationFamilyAdapter::resume(
                description,
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
                Box::new(move |authenticated_continuation| {
                    let resumed_runtime_plan = selected_galois_proof_runtime_plan(
                        resumed_preparation_source.canonical_application_statement_bytes(),
                        resumed_preparation_source.batch_schedule_position(),
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    let prepared_attempt = resolve_galois_prepared_attempt(
                        action_randomness_handle,
                        verified_reservation_binding,
                        &board_source,
                        &resumed_preparation_source,
                        authenticated_continuation,
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    prepare_galois_common_generation(
                        setup_generation_authority_handle,
                        &resumed_preparation_source,
                        prepared_attempt,
                        resumed_runtime_plan.relation_plan,
                        resumed_runtime_plan.limits,
                    )
                    .map(|(prepared_generation, _)| prepared_generation)
                    .map_err(resumed_generation_preparation_error)
                }),
            );
            (adapter, generated_source_authority)
        }
    };
    let generation_source_handle = GALOIS_GENERATION_SOURCE_REGISTRY.with(|registry| {
        registry.borrow_mut().retain(PendingGeneratedGaloisSource {
            setup_generation_authority_identifier: setup_generation_authority_handle,
            _retained_preparation_source: preparation_source,
            generated_source_authority,
            component_readback_lifecycle: GaloisComponentReadbackLifecycle::Available,
        })
    })?;
    match retain_common_proof_generation_family_adapter(generation_family_adapter) {
        Ok(adapter_handle) => Ok((adapter_handle, generation_source_handle)),
        Err(error) => {
            GALOIS_GENERATION_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(generation_source_handle))?;
            Err(GaloisKeyShareRuntimeError::Runtime(error))
        }
    }
}

fn begin_galois_verification_ingress(
    selected_suite_handle: u32,
    prepackage_catalog_handle: u32,
    roster_position: u16,
) -> Result<u32, CommonProofRuntimeError> {
    let mut statement_source = Some(take_prepackage_galois_statement_source(
        prepackage_catalog_handle,
        roster_position,
    )?);
    let session_result = (|| {
        let statement_source_ref = statement_source
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let proof_application_slot = statement_source_ref
            .proof_application_binding()
            .application_slot();
        if proof_application_slot.application_statement_schema_identifier()
            != ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            || proof_application_slot.roster_position() != Some(roster_position)
            || proof_application_slot.schedule_position()
                != Some(SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION)
            || proof_application_slot.producer_sequence().is_some()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let canonical_application_statement_bytes =
            statement_source_ref.canonical_application_statement_bytes();
        let statement = decode_selected_galois_key_share_statement(
            canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                proof_application_slot.suite_identifier().into_bytes(),
                proof_application_slot.schedule_position(),
                None,
            ),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let selected_positions = selected_evaluator_galois_entry_positions()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if statement.roster_position() != roster_position
            || statement.batch_schedule_position()
                != SELECTED_GALOIS_KEY_SHARE_BATCH_SCHEDULE_POSITION
            || statement.ordered_contribution_roots().len() != selected_positions.len()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let ordered_topologies =
            with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
                if selected_suite.protocol_version() != FOUNDATION_PROFILE.protocol_version
                    || selected_suite.suite_identifier()
                        != proof_application_slot.suite_identifier().into_bytes()
                {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding);
                }
                selected_positions
                    .iter()
                    .map(|position| match position.key_kind() {
                        SelectedEvaluatorEntryKind::Galois { catalog_level, .. } => {
                            KeySwitchComponentMaterialTopology::from_selected_suite_at_level(
                                selected_suite,
                                catalog_level,
                            )
                            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
                        }
                        SelectedEvaluatorEntryKind::Relinearization { .. } => {
                            Err(CommonProofRuntimeError::WrongVerificationBinding)
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()
            })??;
        let (roster_hash, ordered_auxiliary_roots) = with_prepackage_generated_galois_source(
            prepackage_catalog_handle,
            roster_position,
            |generated_source| {
                if generated_source.protocol_version() != FOUNDATION_PROFILE.protocol_version
                    || generated_source.suite_identifier()
                        != proof_application_slot.suite_identifier().into_bytes()
                    || generated_source.ceremony_context_hash()
                        != proof_application_slot.ceremony_context_hash().into_bytes()
                    || generated_source.action_context_hash()
                        != proof_application_slot.action_context_hash().into_bytes()
                    || generated_source.setup_proof_context_hash()
                        != statement.setup_proof_context_hash()
                    || generated_source.participant_identity() != statement.participant_identity()
                    || generated_source.roster_position() != roster_position
                    || generated_source.batch_schedule_position()
                        != statement.batch_schedule_position()
                    || generated_source.anchor_commitment_roots()
                        != statement.anchor_commitment_roots()
                    || generated_source.canonical_application_statement_bytes()
                        != canonical_application_statement_bytes
                    || generated_source.ordered_auxiliary_roots().len() != selected_positions.len()
                    || generated_source
                        .ordered_auxiliary_roots()
                        .iter()
                        .zip(&selected_positions)
                        .any(|(root, position)| root.position() != *position)
                {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding);
                }
                Ok((
                    generated_source.roster_hash(),
                    generated_source.ordered_auxiliary_roots().to_vec(),
                ))
            },
        )?;
        let mut ordered_components = Vec::new();
        ordered_components
            .try_reserve_exact(selected_positions.len())
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        for (component_ordinal, (topology, expected_contribution_root)) in ordered_topologies
            .into_iter()
            .zip(statement.ordered_contribution_roots().iter().copied())
            .enumerate()
        {
            let logical_schedule_position = u32::try_from(component_ordinal)
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
            let context = SetupPublicPolynomialContext::new(
                statement.setup_proof_context_hash(),
                SetupPublicPolynomialRootRole::GaloisKeyShare,
                Some(statement.participant_identity()),
                Some(roster_position),
                Some(logical_schedule_position),
                None,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            ordered_components.push(GaloisVerificationComponentIngress {
                topology,
                context,
                expected_contribution_root,
                application_owned_tree: None,
            });
        }
        Ok(GaloisVerificationIngress {
            prepackage_catalog_handle,
            roster_position,
            roster_hash,
            statement_source: statement_source.take(),
            ordered_auxiliary_roots,
            ordered_components,
            next_component_ordinal: 0,
            active_ingress: None,
        })
    })();
    let session = match session_result {
        Ok(session) => session,
        Err(error) => {
            restore_prepackage_galois_statement_source(
                prepackage_catalog_handle,
                roster_position,
                statement_source
                    .take()
                    .expect("failed Galois ingress preparation retains its statement source"),
            )?;
            return Err(error);
        }
    };
    match GALOIS_VERIFICATION_INGRESS_REGISTRY
        .with(|registry| registry.borrow_mut().retain_recovering(session))
    {
        Ok(handle) => Ok(handle),
        Err((error, mut session)) => {
            let statement_source = session
                .statement_source
                .take()
                .expect("unretained Galois ingress retains its statement source");
            restore_prepackage_galois_statement_source(
                prepackage_catalog_handle,
                roster_position,
                statement_source,
            )?;
            Err(error)
        }
    }
}

fn discard_galois_verification_ingress(ingress_handle: u32) -> Result<(), CommonProofRuntimeError> {
    let mut ingress = GALOIS_VERIFICATION_INGRESS_REGISTRY
        .with(|registry| registry.borrow_mut().take(ingress_handle))?;
    if let Some(statement_source) = ingress.statement_source.take() {
        restore_prepackage_galois_statement_source(
            ingress.prepackage_catalog_handle,
            ingress.roster_position,
            statement_source,
        )?;
    }
    Ok(())
}

fn begin_galois_component_ingress(
    ingress_handle: u32,
    component_ordinal: usize,
    stream_descriptor: StreamDescriptor,
) -> Result<(), CommonProofRuntimeError> {
    GALOIS_VERIFICATION_INGRESS_REGISTRY.with(|registry| {
        registry.borrow_mut().with_mut(ingress_handle, |ingress| {
            let statement_source = ingress
                .statement_source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            let proof_application_slot = statement_source
                .proof_application_binding()
                .application_slot();
            let ownership_binding = ComponentMaterialOwnershipBinding::from_verified_application(
                proof_application_slot.suite_identifier().into_bytes(),
                proof_application_slot.action_context_hash().into_bytes(),
                statement_source.application_statement_hash().into_bytes(),
            );
            ingress.begin_component(component_ordinal, stream_descriptor, ownership_binding)
        })
    })
}

fn prepare_galois_verification_adapter(
    selected_suite_handle: u32,
    ingress_handle: u32,
) -> Result<(u32, u32), CommonProofRuntimeError> {
    let adapter_reservation_handle = reserve_common_proof_verification_family_adapter()?;
    let terminal_source_reservation_handle = match GALOIS_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().reserve())
    {
        Ok(handle) => handle,
        Err(error) => {
            cancel_common_proof_verification_family_adapter_reservation(adapter_reservation_handle)
                .expect("uncommitted common-proof adapter reservation remains live");
            return Err(error);
        }
    };

    let borrowed_preflight = GALOIS_VERIFICATION_INGRESS_REGISTRY.with(|registry| {
        registry.borrow_mut().with_mut(ingress_handle, |ingress| {
            if !ingress.is_complete() {
                return Err(CommonProofRuntimeError::WrongOperationPhase);
            }
            let statement_source = ingress
                .statement_source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
            let mut ordered_component_trees = Vec::new();
            ordered_component_trees
                .try_reserve_exact(ingress.ordered_components.len())
                .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
            for component in &ingress.ordered_components {
                ordered_component_trees.push(
                    component
                        .application_owned_tree
                        .as_ref()
                        .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
                        .tree(),
                );
            }
            let statement_trees = with_prepackage_relinearization_source(
                ingress.prepackage_catalog_handle,
                ingress.roster_position,
                |relinearization_source| {
                    VerifiedStatementOwnedTree::from_verified_galois_key_share_statement_sources(
                        statement_source,
                        relinearization_source,
                        &ordered_component_trees,
                    )
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
                },
            )?;
            preflight_reserved_common_proof_verification_family_adapter_from_upstream(
                adapter_reservation_handle,
                |upstream_inputs| {
                    let selected_suite_handle =
                        CommonProofSelectedSuiteCapabilityHandle::from_identifier(
                            selected_suite_handle,
                        );
                    upstream_inputs
                        .preflight_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
                            &selected_suite_handle,
                            statement_source,
                            &statement_trees,
                            &ingress.ordered_auxiliary_roots,
                        )
                },
            )?;
            Ok(statement_trees)
        })
    });
    let statement_trees = match borrowed_preflight {
        Ok(statement_trees) => statement_trees,
        Err(error) => {
            cancel_common_proof_verification_family_adapter_reservation(adapter_reservation_handle)
                .expect("failed Galois preflight retains its common-proof reservation");
            GALOIS_VERIFICATION_TERMINAL_SOURCE_REGISTRY
                .with(|registry| {
                    registry
                        .borrow_mut()
                        .cancel_reservation(terminal_source_reservation_handle)
                })
                .expect("failed Galois preflight retains its terminal reservation");
            return Err(error);
        }
    };

    let mut ingress = GALOIS_VERIFICATION_INGRESS_REGISTRY
        .with(|registry| registry.borrow_mut().take(ingress_handle))
        .expect("preflighted Galois ingress remains live during commit");
    let component_count = ingress.ordered_components.len();
    let mut ordered_contribution_trees = Vec::with_capacity(component_count);
    let mut ordered_materials = Vec::with_capacity(component_count);
    for component in &mut ingress.ordered_components {
        let recomputed = component
            .application_owned_tree
            .take()
            .expect("preflighted Galois component remains available during commit");
        let (material, tree) = recomputed.into_parts();
        ordered_contribution_trees.push(tree);
        ordered_materials.push(material);
    }
    let statement_source = ingress
        .statement_source
        .take()
        .expect("preflighted Galois statement source remains available during commit");
    let canonical_application_statement_bytes = statement_source
        .canonical_application_statement_bytes()
        .to_vec();
    let terminal_statement_trees = statement_trees.clone();
    let adapter_auxiliary_roots = ingress.ordered_auxiliary_roots.clone();
    let terminal_source = GaloisVerificationTerminalSource {
        prepackage_catalog_handle: ingress.prepackage_catalog_handle,
        roster_hash: ingress.roster_hash,
        canonical_application_statement_bytes,
        statement_trees: terminal_statement_trees,
        ordered_auxiliary_roots: ingress.ordered_auxiliary_roots,
        ordered_contribution_trees,
        ordered_materials,
    };
    let adapter_handle = commit_reserved_common_proof_verification_family_adapter_from_upstream(
        adapter_reservation_handle,
        move |upstream_inputs| {
            let selected_suite_handle =
                CommonProofSelectedSuiteCapabilityHandle::from_identifier(selected_suite_handle);
            upstream_inputs
                    .prepare_preflighted_statement_tree_and_auxiliary_root_family_verification_without_evaluator(
                        &selected_suite_handle,
                        statement_source,
                        statement_trees,
                        adapter_auxiliary_roots,
                    )
        },
    );
    GALOIS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .commit_reserved(terminal_source_reservation_handle, terminal_source)
    });
    Ok((adapter_handle, terminal_source_reservation_handle))
}

fn finish_galois_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source = GALOIS_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
    let terminal_source_cell = RefCell::new(Some(terminal_source));
    let result = super::preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |borrowed_proof| {
            let terminal_source = terminal_source_cell.borrow();
            let terminal_source = terminal_source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight =
                VerifiedGaloisSourceMaterialBatchPreflight::from_borrowed_common_proof(
                    borrowed_proof,
                    &terminal_source.canonical_application_statement_bytes,
                    terminal_source.roster_hash,
                    &terminal_source.statement_trees,
                    &terminal_source.ordered_contribution_trees,
                    &terminal_source.ordered_materials,
                    &terminal_source.ordered_auxiliary_roots,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let destination_preflight = preflight_prepackage_galois_source_slot(
                terminal_source.prepackage_catalog_handle,
                &terminal_preflight,
            )?;
            Ok((terminal_preflight, destination_preflight))
        },
        |verified_proof, (terminal_preflight, destination_preflight)| {
            let terminal_source = terminal_source_cell
                .borrow_mut()
                .take()
                .expect("Galois terminal preflight retained the exact source");
            let terminal = terminal_preflight.complete(
                verified_proof,
                &terminal_source.canonical_application_statement_bytes,
                terminal_source.ordered_contribution_trees,
                terminal_source.ordered_materials,
                terminal_source.ordered_auxiliary_roots,
            );
            commit_prepackage_galois_source(destination_preflight, terminal);
        },
    );
    if result.is_err()
        && let Some(terminal_source) = terminal_source_cell.into_inner()
    {
        GALOIS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .restore(terminal_source_handle, terminal_source)
        })?;
    }
    result
}

fn commit_generated_galois_source(
    accepted_setup_package_builder_handle: u32,
    prepackage_catalog_handle: u32,
    generated_common_proof_handle: u32,
    generation_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let pending_source = take_pending_generated_galois_source(generation_source_handle)?;
    if let Err(error) = pending_source.require_completed_component_readback() {
        restore_pending_generated_galois_source(generation_source_handle, pending_source)?;
        return Err(error);
    }
    let preflight = match preflight_prepackage_generated_galois_source_slot(
        prepackage_catalog_handle,
        generated_common_proof_handle,
        pending_source.generated_source_authority(),
    ) {
        Ok(preflight) => preflight,
        Err(error) => {
            restore_pending_generated_galois_source(generation_source_handle, pending_source)?;
            return Err(error);
        }
    };
    if let Err(error) = add_generated_proof_source_to_accepted_setup_package_builder(
        accepted_setup_package_builder_handle,
        generated_common_proof_handle,
        pending_source
            .generated_source_authority()
            .canonical_application_statement_bytes(),
    ) {
        restore_pending_generated_galois_source(generation_source_handle, pending_source)?;
        return Err(error);
    }
    commit_prepackage_generated_galois_source(
        preflight,
        pending_source.into_generated_source_authority(),
    );
    Ok(())
}

fn open_generated_galois_component_readback(
    generation_source_handle: u32,
) -> Result<u32, GaloisKeyShareRuntimeError> {
    GALOIS_GENERATION_SOURCE_REGISTRY.with(|source_registry| {
        let mut source_registry = source_registry.borrow_mut();
        let pending_source = source_registry.source_mut(generation_source_handle)?;
        if pending_source.component_readback_lifecycle
            != GaloisComponentReadbackLifecycle::Available
        {
            return Err(GaloisKeyShareRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        let readback = GaloisGeneratedComponentReadback::from_pending_source(
            generation_source_handle,
            pending_source,
        )?;
        let readback_handle = GALOIS_COMPONENT_READBACK_REGISTRY
            .with(|readback_registry| readback_registry.borrow_mut().retain(readback))?;
        pending_source.component_readback_lifecycle =
            GaloisComponentReadbackLifecycle::Active(readback_handle);
        Ok(readback_handle)
    })
}

fn finish_generated_galois_component_readback(
    generation_source_handle: u32,
    readback_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    GALOIS_GENERATION_SOURCE_REGISTRY.with(|source_registry| {
        let mut source_registry = source_registry.borrow_mut();
        let pending_source = source_registry.source_mut(generation_source_handle)?;
        if pending_source.component_readback_lifecycle
            != GaloisComponentReadbackLifecycle::Active(readback_handle)
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        GALOIS_COMPONENT_READBACK_REGISTRY.with(|readback_registry| {
            readback_registry
                .borrow_mut()
                .finish(readback_handle, generation_source_handle)
        })?;
        pending_source.component_readback_lifecycle = GaloisComponentReadbackLifecycle::Completed;
        Ok(())
    })
}

fn cancel_generated_galois_component_readback(
    generation_source_handle: u32,
    readback_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    GALOIS_GENERATION_SOURCE_REGISTRY.with(|source_registry| {
        let mut source_registry = source_registry.borrow_mut();
        let pending_source = source_registry.source_mut(generation_source_handle)?;
        if pending_source.component_readback_lifecycle
            != GaloisComponentReadbackLifecycle::Active(readback_handle)
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        GALOIS_COMPONENT_READBACK_REGISTRY.with(|readback_registry| {
            readback_registry
                .borrow_mut()
                .cancel(readback_handle, generation_source_handle)
        })?;
        pending_source.component_readback_lifecycle = GaloisComponentReadbackLifecycle::Cancelled;
        Ok(())
    })
}

fn discard_generated_galois_source(
    generation_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let pending_source = take_pending_generated_galois_source(generation_source_handle)?;
    if let GaloisComponentReadbackLifecycle::Active(readback_handle) =
        pending_source.component_readback_lifecycle
        && let Err(error) = GALOIS_COMPONENT_READBACK_REGISTRY.with(|readback_registry| {
            readback_registry
                .borrow_mut()
                .cancel(readback_handle, generation_source_handle)
        })
    {
        restore_pending_generated_galois_source(generation_source_handle, pending_source)?;
        return Err(error);
    }
    Ok(())
}

fn read_generated_galois_component_chunk(
    readback_handle: u32,
    component_ordinal: usize,
    chunk_index: usize,
    output: &mut [u8],
) -> Result<(), GaloisKeyShareRuntimeError> {
    GALOIS_COMPONENT_READBACK_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let readback = registry.entry_mut(readback_handle)?;
        let expected_byte_length =
            readback.expected_chunk_byte_length(component_ordinal, chunk_index)?;
        if output.len() != expected_byte_length {
            return Err(GaloisKeyShareRuntimeError::InvalidInput);
        }
        let setup_generation_authority_handle = SetupGenerationAuthorityHandle::from_identifier(
            readback.setup_generation_authority_handle.identifier(),
        );
        let stream_descriptor = readback
            .current_component(component_ordinal)?
            .stream_descriptor
            .clone();
        with_setup_generation_galois_public_component_chunk(
            &setup_generation_authority_handle,
            component_ordinal,
            &stream_descriptor,
            chunk_index,
            |source_chunk| {
                readback.authenticate_and_copy_chunk(
                    component_ordinal,
                    chunk_index,
                    source_chunk,
                    output,
                )
            },
        )??;
        Ok(())
    })
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn runtime_error_status(error: GaloisKeyShareRuntimeError) -> u32 {
    match error {
        GaloisKeyShareRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        GaloisKeyShareRuntimeError::GenerationPreparation(error) => match error {
            SetupGaloisGenerationPreparationError::Refusal(refusal_reason) => {
                refusal_status(refusal_reason)
            }
            SetupGaloisGenerationPreparationError::Runtime(error) => {
                super::runtime_ffi::runtime_error_status(error)
            }
            SetupGaloisGenerationPreparationError::Preparation(error) => match error {
                CommonProofGenerationPreparationError::Runtime(error) => {
                    super::runtime_ffi::runtime_error_status(error)
                }
                CommonProofGenerationPreparationError::Generation(error) => {
                    let _ = error;
                    refusal_status(RefusalReason::OutsideSupportedProfile)
                }
            },
            SetupGaloisGenerationPreparationError::Prover(error) => {
                let _ = error;
                refusal_status(RefusalReason::InvalidArithmeticRelation)
            }
        },
        GaloisKeyShareRuntimeError::Foundation(error) => refusal_status(error.refusal_reason),
        GaloisKeyShareRuntimeError::ActionRandomnessRuntime(status)
        | GaloisKeyShareRuntimeError::BoardRuntime(status)
        | GaloisKeyShareRuntimeError::StateRuntime(status) => status,
        GaloisKeyShareRuntimeError::Refusal(refusal_reason) => refusal_status(refusal_reason),
        GaloisKeyShareRuntimeError::InvalidInput => {
            refusal_status(RefusalReason::WrongTypeOrLength)
        }
        GaloisKeyShareRuntimeError::Accounting(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        GaloisKeyShareRuntimeError::Profile(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        GaloisKeyShareRuntimeError::Relation(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        GaloisKeyShareRuntimeError::RelationCapability(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
    declared_byte_length: usize,
) -> Result<[u8; BYTE_LENGTH], GaloisKeyShareRuntimeError> {
    if pointer.is_null() || declared_byte_length != BYTE_LENGTH {
        return Err(GaloisKeyShareRuntimeError::InvalidInput);
    }
    let bytes = unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) };
    bytes
        .try_into()
        .map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)
}

unsafe fn variable_input<'input>(
    pointer: *const u8,
    declared_byte_length: usize,
) -> Result<&'input [u8], GaloisKeyShareRuntimeError> {
    if pointer.is_null() || declared_byte_length == 0 {
        return Err(GaloisKeyShareRuntimeError::InvalidInput);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, declared_byte_length) })
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_from_ffi_inputs(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    generation_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: GaloisGenerationMode,
) -> u32 {
    let result = (|| {
        if generation_source_handle_output_pointer.is_null() {
            return Err(GaloisKeyShareRuntimeError::InvalidInput);
        }
        let state_verifier_session_capability = unsafe {
            fixed_input::<STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        }?;
        let board_verifier_session_capability = unsafe {
            fixed_input::<BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        }?;
        let checkpoint_lineage_identifier = unsafe {
            fixed_input::<ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                checkpoint_lineage_identifier_pointer,
                checkpoint_lineage_identifier_byte_length,
            )
        }?;
        prepare_galois_generation(
            selected_suite_handle,
            setup_generation_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            &state_verifier_session_capability,
            verified_reservation_handle,
            board_verifier_session_handle,
            &board_verifier_session_capability,
            setup_intent_object_handle,
            checkpoint_lineage_identifier,
            generation_mode,
        )
    })();
    match result {
        Ok((adapter_handle, generation_source_handle)) => {
            unsafe {
                generation_source_handle_output_pointer.write(generation_source_handle);
                write_status(status_pointer, 0);
            }
            adapter_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Retains a fresh suite-fixed Galois generation adapter and its one-shot
/// generation-only source authority.
///
/// # Safety
///
/// Each capability pointer must name its declared readable range. The
/// checkpoint lineage pointer must name exactly 32 readable bytes. The source
/// output and non-null status pointers must each name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_prepare_generation(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    generation_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_from_ffi_inputs(
            selected_suite_handle,
            setup_generation_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            board_verifier_session_handle,
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
            setup_intent_object_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            generation_source_handle_output_pointer,
            status_pointer,
            GaloisGenerationMode::Fresh,
        )
    }
}

/// Retains a resume adapter bound to the exact fresh Galois attempt and
/// authenticated checkpoint schedule.
///
/// # Safety
///
/// Each capability pointer must name its declared readable range. The
/// checkpoint lineage pointer must name exactly 32 readable bytes. The source
/// output and non-null status pointers must each name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_prepare_resumed_generation(
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    generation_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_from_ffi_inputs(
            selected_suite_handle,
            setup_generation_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            board_verifier_session_handle,
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
            setup_intent_object_handle,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            generation_source_handle_output_pointer,
            status_pointer,
            GaloisGenerationMode::Resume,
        )
    }
}

/// Opens the one-pass public-component readback owned by one pending Galois
/// generation source. The returned handle cannot be reopened after completion
/// or cancellation.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_readback_open(
    generation_source_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match open_generated_galois_component_readback(generation_source_handle) {
        Ok(readback_handle) => {
            unsafe { write_status(status_pointer, 0) };
            readback_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Returns the exact suite-fixed ordered component count.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_readback_component_count(
    readback_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = GALOIS_COMPONENT_READBACK_REGISTRY.with(|registry| {
        u32::try_from(registry.borrow().entry(readback_handle)?.component_count())
            .map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)
    });
    match result {
        Ok(component_count) => {
            unsafe { write_status(status_pointer, 0) };
            component_count
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Returns the canonical descriptor encoding length for the current ordered
/// component.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_readback_descriptor_byte_length(
    readback_handle: u32,
    component_ordinal: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| -> Result<u32, GaloisKeyShareRuntimeError> {
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)?;
        GALOIS_COMPONENT_READBACK_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let byte_length = registry
                .entry(readback_handle)?
                .current_component(component_ordinal)?
                .encoded_stream_descriptor
                .len();
            u32::try_from(byte_length).map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)
        })
    })();
    match result {
        Ok(byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            byte_length
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Copies the Rust-minted canonical descriptor for the current ordered
/// component.
///
/// # Safety
///
/// The output pointer must name its declared writable range. A non-null status
/// pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_readback_copy_descriptor(
    readback_handle: u32,
    component_ordinal: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| -> Result<(), GaloisKeyShareRuntimeError> {
        if output_pointer.is_null() {
            return Err(GaloisKeyShareRuntimeError::InvalidInput);
        }
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)?;
        GALOIS_COMPONENT_READBACK_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let descriptor = &registry
                .entry(readback_handle)?
                .current_component(component_ordinal)?
                .encoded_stream_descriptor;
            if output_byte_length != descriptor.len() {
                return Err(GaloisKeyShareRuntimeError::InvalidInput);
            }
            let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
            output.copy_from_slice(descriptor);
            Ok(())
        })
    })();
    match result {
        Ok(()) => {
            unsafe { write_status(status_pointer, 0) };
            0
        }
        Err(error) => {
            let status = runtime_error_status(error);
            unsafe { write_status(status_pointer, status) };
            status
        }
    }
}

/// Copies the Rust-minted material root for the current ordered component.
/// This root binds the authenticated stream to the exact generated
/// application and is never supplied by JavaScript.
///
/// # Safety
///
/// The output pointer must name exactly its declared writable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_readback_copy_material_root(
    readback_handle: u32,
    component_ordinal: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| -> Result<(), GaloisKeyShareRuntimeError> {
        if output_pointer.is_null() || output_byte_length != Hash512::BYTE_LENGTH {
            return Err(GaloisKeyShareRuntimeError::InvalidInput);
        }
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)?;
        GALOIS_COMPONENT_READBACK_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let material_root = registry
                .entry(readback_handle)?
                .current_component(component_ordinal)?
                .material_root;
            let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
            output.copy_from_slice(&material_root);
            Ok(())
        })
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

/// Returns the exact authenticated stream length for the current ordered
/// component.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_readback_total_byte_length(
    readback_handle: u32,
    component_ordinal: u32,
    status_pointer: *mut u32,
) -> u64 {
    let result = (|| -> Result<u64, GaloisKeyShareRuntimeError> {
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)?;
        GALOIS_COMPONENT_READBACK_REGISTRY.with(|registry| {
            Ok(registry
                .borrow()
                .entry(readback_handle)?
                .current_component(component_ordinal)?
                .stream_descriptor
                .total_byte_length)
        })
    })();
    match result {
        Ok(total_byte_length) => {
            unsafe { write_status(status_pointer, 0) };
            total_byte_length
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Authenticates and copies one exact sequential component chunk. Failed
/// order or range checks do not advance the readback cursor.
///
/// # Safety
///
/// The output pointer must name its declared writable range. A non-null status
/// pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_readback_read_chunk(
    readback_handle: u32,
    component_ordinal: u32,
    chunk_index: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| -> Result<(), GaloisKeyShareRuntimeError> {
        if output_pointer.is_null() || output_byte_length == 0 {
            return Err(GaloisKeyShareRuntimeError::InvalidInput);
        }
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)?;
        let chunk_index =
            usize::try_from(chunk_index).map_err(|_| GaloisKeyShareRuntimeError::InvalidInput)?;
        let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
        read_generated_galois_component_chunk(
            readback_handle,
            component_ordinal,
            chunk_index,
            output,
        )
    })();
    match result {
        Ok(()) => {
            unsafe { write_status(status_pointer, 0) };
            0
        }
        Err(error) => {
            let status = runtime_error_status(error);
            unsafe { write_status(status_pointer, status) };
            status
        }
    }
}

/// Completes and releases a fully read component stream while leaving its
/// owning generation source live for package commit.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_galois_key_share_component_readback_finish(
    generation_source_handle: u32,
    readback_handle: u32,
) -> u32 {
    finish_generated_galois_component_readback(generation_source_handle, readback_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// Cancels and releases an incomplete component stream. Cancellation is
/// permanent for the owning generation source.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_galois_key_share_component_readback_cancel(
    generation_source_handle: u32,
    readback_handle: u32,
) -> u32 {
    cancel_generated_galois_component_readback(generation_source_handle, readback_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// Atomically retains one completed generated proof in the next exact package
/// slot, then transfers its generation-only source into the prepackage
/// catalog. The package builder receives the authority-owned canonical
/// statement before the catalog commit; no caller-supplied statement can
/// select or alter the proof binding.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_galois_key_share_commit_generated_source(
    accepted_setup_package_builder_handle: u32,
    prepackage_catalog_handle: u32,
    generated_common_proof_handle: u32,
    generation_source_handle: u32,
) -> u32 {
    commit_generated_galois_source(
        accepted_setup_package_builder_handle,
        prepackage_catalog_handle,
        generated_common_proof_handle,
        generation_source_handle,
    )
    .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// Permanently discards a generation-only Galois source after cancellation.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_galois_key_share_discard_generation_source(
    generation_source_handle: u32,
) -> u32 {
    discard_generated_galois_source(generation_source_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// Begins package-bound positive `0x1217` verification for one exact roster
/// slot after the joint generated-proof/package binding has completed.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_verification_ingress_begin(
    selected_suite_handle: u32,
    prepackage_catalog_handle: u32,
    roster_position: u16,
    status_pointer: *mut u32,
) -> u32 {
    match begin_galois_verification_ingress(
        selected_suite_handle,
        prepackage_catalog_handle,
        roster_position,
    ) {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

/// Begins the ownership-bound authenticated pass for the next exact Galois
/// component. The descriptor bytes must be the canonical foundation stream
/// descriptor carried by the component backing.
///
/// # Safety
///
/// The descriptor pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_begin(
    ingress_handle: u32,
    component_ordinal: u32,
    stream_descriptor_pointer: *const u8,
    stream_descriptor_byte_length: usize,
) -> u32 {
    let result = (|| {
        let descriptor_bytes =
            unsafe { variable_input(stream_descriptor_pointer, stream_descriptor_byte_length) }
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let stream_descriptor =
            StreamDescriptor::decode(descriptor_bytes, &CanonicalDecodeLimits::default())
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        begin_galois_component_ingress(ingress_handle, component_ordinal, stream_descriptor)
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// Absorbs one exact canonical component chunk into the active one-pass
/// application-owned stream.
///
/// # Safety
///
/// The chunk pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_component_absorb_chunk(
    ingress_handle: u32,
    component_ordinal: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    let result = (|| {
        let chunk_bytes = unsafe { variable_input(chunk_pointer, chunk_byte_length) }
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let component_ordinal = usize::try_from(component_ordinal)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let chunk_index = usize::try_from(chunk_index)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        GALOIS_VERIFICATION_INGRESS_REGISTRY.with(|registry| {
            registry.borrow_mut().with_mut(ingress_handle, |ingress| {
                ingress.absorb_active_chunk(component_ordinal, chunk_index, chunk_bytes)
            })
        })
    })();
    result.map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_galois_key_share_component_finish(
    ingress_handle: u32,
    component_ordinal: u32,
) -> u32 {
    usize::try_from(component_ordinal)
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        .and_then(|component_ordinal| {
            GALOIS_VERIFICATION_INGRESS_REGISTRY.with(|registry| {
                registry.borrow_mut().with_mut(ingress_handle, |ingress| {
                    ingress.finish_component(component_ordinal)
                })
            })
        })
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// Consumes a complete one-pass component ingress into the generic verifier
/// adapter and returns the one-shot family terminal source beside it.
///
/// # Safety
///
/// The terminal-source output and non-null status pointers must each name one
/// writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_galois_key_share_prepare_verification(
    selected_suite_handle: u32,
    ingress_handle: u32,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    if terminal_source_handle_output_pointer.is_null() {
        unsafe {
            write_status(
                status_pointer,
                super::runtime_ffi::runtime_error_status(
                    CommonProofRuntimeError::WrongVerificationBinding,
                ),
            )
        };
        return 0;
    }
    match prepare_galois_verification_adapter(selected_suite_handle, ingress_handle) {
        Ok((adapter_handle, terminal_source_handle)) => {
            unsafe {
                terminal_source_handle_output_pointer.write(terminal_source_handle);
                write_status(status_pointer, 0);
            }
            adapter_handle
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_galois_key_share_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> u32 {
    finish_galois_verification(verified_common_proof_handle, terminal_source_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// Cancels an incomplete one-pass ingress and restores its exact package-
/// backed statement source for a fresh attempt.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_galois_key_share_discard_verification_ingress(
    ingress_handle: u32,
) -> u32 {
    discard_galois_verification_ingress(ingress_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

/// Drops a family terminal source after its generic verifier operation was
/// explicitly cancelled.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_galois_key_share_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    GALOIS_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(terminal_source_handle)
            .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::{
        CanonicalStreamDomain, CanonicalStreamVerifier, derive_canonical_stream_descriptor,
    };

    fn readback_binding(
        canonical_bytes: &[u8],
        material_root_byte: u8,
    ) -> GaloisGeneratedComponentReadbackBinding {
        let stream_descriptor = derive_canonical_stream_descriptor(
            CanonicalStreamDomain::EvaluatorKeyStore,
            canonical_bytes,
        )
        .expect("test descriptor derives from canonical bytes");
        let mut verifier = CanonicalStreamVerifier::new(
            CanonicalStreamDomain::EvaluatorKeyStore,
            stream_descriptor.clone(),
        )
        .expect("test component verification begins");
        for (chunk_index, chunk) in canonical_bytes
            .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
            .enumerate()
        {
            assert!(verifier.absorb_chunk(chunk_index, chunk).is_valid());
        }
        let summary = verifier
            .finish_with_summary()
            .into_result()
            .expect("test component summary is verifier minted");
        let authenticated_readback =
            CanonicalStreamReadbackVerifier::new(CanonicalStreamDomain::EvaluatorKeyStore, summary)
                .expect("test authenticated readback begins");
        GaloisGeneratedComponentReadbackBinding {
            material_root: [material_root_byte; Hash512::BYTE_LENGTH],
            encoded_stream_descriptor: stream_descriptor
                .encode()
                .expect("test descriptor encodes")
                .into_boxed_slice(),
            stream_descriptor,
            authenticated_readback: Some(authenticated_readback),
        }
    }

    fn readback_source(
        owner_generation_source_handle: u32,
        components: &[(&[u8], u8)],
    ) -> GaloisGeneratedComponentReadback {
        GaloisGeneratedComponentReadback {
            owner_generation_source_handle,
            setup_generation_authority_handle: SetupGenerationAuthorityHandle::from_identifier(91),
            ordered_components: components
                .iter()
                .map(|(canonical_bytes, material_root_byte)| {
                    readback_binding(canonical_bytes, *material_root_byte)
                })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            next_component_ordinal: 0,
            next_chunk_index: 0,
        }
    }

    #[test]
    fn generated_component_readback_requires_exact_component_chunk_and_output_order() {
        let first_component = vec![11_u8; 31];
        let second_component = vec![22_u8; 47];
        let mut source = readback_source(
            7,
            &[
                (first_component.as_slice(), 31),
                (second_component.as_slice(), 47),
            ],
        );

        assert!(matches!(
            source.current_component(1),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));
        assert!(matches!(
            source.expected_chunk_byte_length(0, 1),
            Err(GaloisKeyShareRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase
            ))
        ));
        let mut short_output = vec![0_u8; first_component.len() - 1];
        assert!(matches!(
            source.authenticate_and_copy_chunk(0, 0, &first_component, &mut short_output),
            Err(GaloisKeyShareRuntimeError::InvalidInput)
        ));
        assert_eq!(source.next_component_ordinal, 0);
        assert_eq!(source.next_chunk_index, 0);

        let mut first_output = vec![0_u8; first_component.len()];
        source
            .authenticate_and_copy_chunk(0, 0, &first_component, &mut first_output)
            .expect("the exact first component is released");
        assert_eq!(first_output, first_component);
        assert_eq!(source.next_component_ordinal, 1);
        assert_eq!(source.next_chunk_index, 0);

        assert!(matches!(
            source.current_component(0),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));
        let mut second_output = vec![0_u8; second_component.len()];
        source
            .authenticate_and_copy_chunk(1, 0, &second_component, &mut second_output)
            .expect("the exact second component is released");
        assert_eq!(second_output, second_component);
        assert!(source.is_complete());
    }

    #[test]
    fn generated_component_readback_authenticates_before_copying() {
        let canonical_component = vec![73_u8; 29];
        let substituted_component = vec![74_u8; canonical_component.len()];
        let mut source = readback_source(13, &[(canonical_component.as_slice(), 73)]);
        let mut output = vec![99_u8; canonical_component.len()];

        assert!(matches!(
            source.authenticate_and_copy_chunk(0, 0, &substituted_component, &mut output,),
            Err(GaloisKeyShareRuntimeError::Refusal(
                RefusalReason::WrongHashOrRoot
            ))
        ));
        assert_eq!(output, vec![99_u8; canonical_component.len()]);
        assert_eq!(source.next_component_ordinal, 0);
        assert_eq!(source.next_chunk_index, 0);
    }

    #[test]
    fn generated_component_readback_registry_releases_and_never_reuses_handles() {
        let canonical_component = vec![8_u8; 17];
        let mut registry = SingleActiveGaloisComponentReadbackRegistry::default();
        let first_handle = registry
            .retain(readback_source(41, &[(canonical_component.as_slice(), 8)]))
            .expect("first readback retains");
        assert_eq!(first_handle, 1);
        assert!(matches!(
            registry.finish(first_handle, 41),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));
        assert!(matches!(
            registry.cancel(first_handle, 42),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
        registry
            .cancel(first_handle, 41)
            .expect("the owning source cancels its readback");
        assert!(matches!(
            registry.entry(first_handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));

        let second_handle = registry
            .retain(readback_source(42, &[(canonical_component.as_slice(), 9)]))
            .expect("a fresh readback retains after release");
        assert_eq!(second_handle, 2);
        assert!(matches!(
            registry.entry(first_handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
        assert_eq!(registry.entry(second_handle).unwrap().next_chunk_index, 0);
    }

    #[test]
    fn generated_component_readback_registry_finishes_only_the_complete_owner() {
        let canonical_component = vec![19_u8; 23];
        let mut registry = SingleActiveGaloisComponentReadbackRegistry::default();
        let handle = registry
            .retain(readback_source(57, &[(canonical_component.as_slice(), 19)]))
            .expect("readback retains");
        let mut output = vec![0_u8; canonical_component.len()];
        registry
            .entry_mut(handle)
            .unwrap()
            .authenticate_and_copy_chunk(0, 0, &canonical_component, &mut output)
            .expect("component readback completes");
        assert!(matches!(
            registry.finish(handle, 58),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));
        registry
            .finish(handle, 57)
            .expect("complete owning readback releases");
        assert!(matches!(
            registry.entry(handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }
}
