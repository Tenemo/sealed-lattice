//! Browser/WASM lifecycle owner for the selected paired target-release proof.
//!
//! The production adapter is intentionally kept in this family module so its
//! finalized-target, accepted-setup, reset-safe state, and canonical-stream
//! authorities cannot be replaced by caller-authored statement fields.

use core::slice;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use zeroize::Zeroizing;

use crate::{
    bgv::{
        setup::{
            VerifiedAcceptedSetupAuthorityHandle, lease_verified_participant_target_release_source,
            with_verified_accepted_setup_authority,
        },
        target_decryption::kllps_release::{
            KLLPS_RECONSTRUCTION_THRESHOLD, KllpsPartialDecryptionRoleStream,
            KllpsParticipantReleaseBinding, KllpsReconstructionTargetPair, KllpsReleaseBinding,
            KllpsShareVerificationSources, KllpsTargetPair,
            KllpsTargetReleaseGenerationPreparationError, KllpsTargetReleaseWitnessSource,
            VerifiedKllpsPairedShare, VerifiedKllpsPairedSharePreflight,
            generate_authorized_factor_four_paired_partial_decryption,
            lease_authorized_target_release_witness_source,
            preflight_kllps_paired_share_from_borrowed_common_proof,
            reconstruct_factor_four_finalized_target_pair,
            verified_target_release_column_evaluator,
            verify_finalized_kllps_reconstruction_target_pair, verify_finalized_kllps_target_pair,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode},
    foundation::{
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, CanonicalDecodeLimits,
        FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, FOUNDATION_PROFILE, FoundationObjectType,
        FoundationSchemaError, Hash512, ParticipantIdentity, PreparedActionProofAttemptSource,
        ProofApplicationBinding, ProofApplicationSlot, ProofApplicationSlotCeilings,
        ProofObjectHeader, RefusalReason, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
        StateCapabilityKind, StateVerifier, StreamDescriptor, VerifiedBoardApplicationSource,
        VerifiedFinality, VerifiedStateOutput, VerifiedStateReservation,
        VerifiedStateReservationRuntimeBinding, resolve_prepared_action_proof_attempt_source,
        resolve_verified_board_application_sources,
        retain_action_private_randomness_for_exact_family, verified_state_reservation_binding,
        with_verified_finality, with_verified_state_reservation,
        with_verified_state_reservation_and_output,
    },
};

use super::application_statement::SelectedApplicationStatementError;
use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    bind_generated_common_proof_to_verified_board_source,
    preflight_and_consume_verified_common_proof_with_family_terminal,
    retain_common_proof_generation_family_adapter,
    retain_common_proof_verification_family_adapter_from_upstream,
    with_common_proof_selected_suite,
};
use super::{
    CommonProofGenerationPreparationError, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofSelectedSuiteCapabilityHandle, PreparedCommonProofGeneration, ProofProfileError,
    RelationPlanError, SelectedProofAccountingError, VerifiedCommonProofCapabilityHandle,
    VerifiedCommonProofStatementSource, VerifiedStatementOwnedTree,
    canonical_selected_target_share_statement, selected_proof_runtime_limits,
    selected_relation_plan_check_context, selected_target_release_relation,
};

const CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH: usize = 32;
const HANDLE_BYTE_LENGTH: usize = core::mem::size_of::<u32>();
const TARGET_ROLE_COUNT: usize = 2;
const RECONSTRUCTED_SLOT_BYTE_LENGTH: usize = core::mem::size_of::<u32>();

#[derive(Debug)]
enum TargetReleaseRuntimeError {
    Accounting(SelectedProofAccountingError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    Runtime(CommonProofRuntimeError),
    GenerationPreparation(KllpsTargetReleaseGenerationPreparationError),
    Canonical(CanonicalError),
    Foundation(FoundationSchemaError),
    AuthorityRuntime(u32),
    ActionRandomnessRuntime(u32),
    BoardRuntime(u32),
    Refusal(RefusalReason),
    InvalidInput,
}

impl From<SelectedProofAccountingError> for TargetReleaseRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<ProofProfileError> for TargetReleaseRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for TargetReleaseRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for TargetReleaseRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofRuntimeError> for TargetReleaseRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<KllpsTargetReleaseGenerationPreparationError> for TargetReleaseRuntimeError {
    fn from(error: KllpsTargetReleaseGenerationPreparationError) -> Self {
        Self::GenerationPreparation(error)
    }
}

impl From<CanonicalError> for TargetReleaseRuntimeError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

impl From<FoundationSchemaError> for TargetReleaseRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

impl From<RefusalReason> for TargetReleaseRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

struct SingleActiveTargetReleaseRegistry<Source> {
    active: Option<(u32, Source)>,
    next_handle: u32,
}

impl<Source> Default for SingleActiveTargetReleaseRegistry<Source> {
    fn default() -> Self {
        Self {
            active: None,
            next_handle: 1,
        }
    }
}

impl<Source> SingleActiveTargetReleaseRegistry<Source> {
    fn retain(&mut self, source: Source) -> Result<u32, CommonProofRuntimeError> {
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

    fn source(&self, handle: u32) -> Result<&Source, CommonProofRuntimeError> {
        self.active
            .as_ref()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn with_mut<Output>(
        &mut self,
        handle: u32,
        operation: impl FnOnce(&mut Source) -> Result<Output, TargetReleaseRuntimeError>,
    ) -> Result<Output, TargetReleaseRuntimeError> {
        let source = self
            .active
            .as_mut()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        operation(source)
    }

    fn take(&mut self, handle: u32) -> Result<Source, CommonProofRuntimeError> {
        self.source(handle)?;
        self.active
            .take()
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(&mut self, handle: u32, source: Source) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.active.is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.active = Some((handle, source));
        Ok(())
    }
}

struct BoundedVerifiedTargetShareRegistry {
    shares: BTreeMap<u32, VerifiedKllpsPairedShare>,
    reserved_handle: Option<u32>,
    next_handle: u32,
}

impl Default for BoundedVerifiedTargetShareRegistry {
    fn default() -> Self {
        Self {
            shares: BTreeMap::new(),
            reserved_handle: None,
            next_handle: 1,
        }
    }
}

impl BoundedVerifiedTargetShareRegistry {
    fn reserve(&mut self) -> Result<u32, CommonProofRuntimeError> {
        let retained_count = self
            .shares
            .len()
            .checked_add(usize::from(self.reserved_handle.is_some()))
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if retained_count >= usize::from(FOUNDATION_PROFILE.participant_count)
            || self.reserved_handle.is_some()
        {
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
        self.reserved_handle = Some(handle);
        Ok(handle)
    }

    fn commit_preflighted(&mut self, handle: u32, share: VerifiedKllpsPairedShare) -> u32 {
        assert_eq!(
            self.reserved_handle.take(),
            Some(handle),
            "target-share destination reservation remains exclusive during commit"
        );
        assert!(
            self.shares.insert(handle, share).is_none(),
            "target-share destination remains vacant during commit"
        );
        handle
    }

    fn release_reservation(&mut self, handle: u32) -> Result<(), CommonProofRuntimeError> {
        if self.reserved_handle != Some(handle) {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        self.reserved_handle = None;
        Ok(())
    }

    fn consume(
        &mut self,
        handle: u32,
    ) -> Result<VerifiedKllpsPairedShare, CommonProofRuntimeError> {
        self.shares
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn reconstruct_and_consume(
        &mut self,
        target_pair: &KllpsReconstructionTargetPair,
        verified_share_handles: &[u32],
    ) -> Result<PendingReconstructedTargetPair, TargetReleaseRuntimeError> {
        if verified_share_handles.len() != KLLPS_RECONSTRUCTION_THRESHOLD
            || verified_share_handles
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
                .len()
                != KLLPS_RECONSTRUCTION_THRESHOLD
        {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let verified_shares = verified_share_handles
            .iter()
            .map(|handle| {
                self.shares
                    .get(handle)
                    .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let reconstructed =
            reconstruct_factor_four_finalized_target_pair(target_pair, &verified_shares)?;
        let (target_identifier_slots, target_order_slots) = reconstructed.decode_logical_slots()?;
        let pending_target_pair =
            PendingReconstructedTargetPair::new(target_identifier_slots, target_order_slots)?;
        for handle in verified_share_handles {
            assert!(
                self.shares.remove(handle).is_some(),
                "preflighted target-release reconstruction shares remain present until commit"
            );
        }
        Ok(pending_target_pair)
    }
}

struct PendingReconstructedTargetPair {
    role_slots: [Option<Vec<u32>>; TARGET_ROLE_COUNT],
    next_role_ordinal: usize,
}

impl PendingReconstructedTargetPair {
    fn new(
        target_identifier_slots: Vec<u64>,
        target_order_slots: Vec<u64>,
    ) -> Result<Self, TargetReleaseRuntimeError> {
        let encoded_role_byte_length = target_identifier_slots
            .len()
            .checked_mul(RECONSTRUCTED_SLOT_BYTE_LENGTH)
            .ok_or(TargetReleaseRuntimeError::InvalidInput)?;
        if target_identifier_slots.is_empty()
            || target_identifier_slots.len() != target_order_slots.len()
            || encoded_role_byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
        {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let target_identifier_slots = target_identifier_slots
            .into_iter()
            .map(u32::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        let target_order_slots = target_order_slots
            .into_iter()
            .map(u32::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        Ok(Self {
            role_slots: [Some(target_identifier_slots), Some(target_order_slots)],
            next_role_ordinal: 0,
        })
    }

    fn slot_count(&self) -> Result<u32, TargetReleaseRuntimeError> {
        let slot_count = self
            .role_slots
            .iter()
            .filter_map(Option::as_ref)
            .next()
            .map(Vec::len)
            .ok_or(TargetReleaseRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ))?;
        u32::try_from(slot_count).map_err(|_| TargetReleaseRuntimeError::InvalidInput)
    }

    fn copy_role(
        &mut self,
        role_ordinal: usize,
        output: &mut [u8],
    ) -> Result<(), TargetReleaseRuntimeError> {
        if role_ordinal != self.next_role_ordinal {
            return Err(TargetReleaseRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        let slots = self
            .role_slots
            .get(role_ordinal)
            .and_then(Option::as_ref)
            .ok_or(TargetReleaseRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ))?;
        let expected_byte_length = slots
            .len()
            .checked_mul(RECONSTRUCTED_SLOT_BYTE_LENGTH)
            .ok_or(TargetReleaseRuntimeError::InvalidInput)?;
        if output.len() != expected_byte_length {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        for (slot, output_word) in slots
            .iter()
            .zip(output.chunks_exact_mut(RECONSTRUCTED_SLOT_BYTE_LENGTH))
        {
            output_word.copy_from_slice(&slot.to_le_bytes());
        }
        self.role_slots[role_ordinal].take();
        self.next_role_ordinal += 1;
        Ok(())
    }

    const fn is_complete(&self) -> bool {
        self.next_role_ordinal == TARGET_ROLE_COUNT
    }
}

struct ReconstructedTargetPairRegistry {
    active: Option<(u32, PendingReconstructedTargetPair)>,
    reserved_handle: Option<u32>,
    next_handle: u32,
}

impl Default for ReconstructedTargetPairRegistry {
    fn default() -> Self {
        Self {
            active: None,
            reserved_handle: None,
            next_handle: 1,
        }
    }
}

impl ReconstructedTargetPairRegistry {
    fn reserve(&mut self) -> Result<u32, CommonProofRuntimeError> {
        if self.active.is_some() || self.reserved_handle.is_some() {
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
        self.reserved_handle = Some(handle);
        Ok(handle)
    }

    fn commit_reserved(&mut self, handle: u32, target_pair: PendingReconstructedTargetPair) -> u32 {
        assert_eq!(
            self.reserved_handle.take(),
            Some(handle),
            "reconstructed target destination reservation remains exclusive during commit"
        );
        assert!(
            self.active.is_none(),
            "reconstructed target destination remains vacant during commit"
        );
        self.active = Some((handle, target_pair));
        handle
    }

    fn release_reservation(&mut self, handle: u32) -> Result<(), CommonProofRuntimeError> {
        if self.reserved_handle != Some(handle) {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        self.reserved_handle = None;
        Ok(())
    }

    fn source(
        &self,
        handle: u32,
    ) -> Result<&PendingReconstructedTargetPair, CommonProofRuntimeError> {
        self.active
            .as_ref()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn with_mut<Output>(
        &mut self,
        handle: u32,
        operation: impl FnOnce(
            &mut PendingReconstructedTargetPair,
        ) -> Result<Output, TargetReleaseRuntimeError>,
    ) -> Result<Output, TargetReleaseRuntimeError> {
        let source = self
            .active
            .as_mut()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        operation(source)
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<PendingReconstructedTargetPair, CommonProofRuntimeError> {
        self.source(handle)?;
        self.active
            .take()
            .map(|(_, source)| source)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn finish(&mut self, handle: u32) -> Result<(), CommonProofRuntimeError> {
        if !self.source(handle)?.is_complete() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.take(handle)?;
        Ok(())
    }
}

struct PendingTargetReleaseGenerationSource {
    release_binding: KllpsReleaseBinding,
    participant_binding: KllpsParticipantReleaseBinding,
    roster_position: u16,
    canonical_application_statement_bytes: Vec<u8>,
    role_stream_descriptors: [StreamDescriptor; TARGET_ROLE_COUNT],
    role_streams: [Option<KllpsPartialDecryptionRoleStream>; TARGET_ROLE_COUNT],
    next_role_ordinal: usize,
    next_chunk_index: usize,
    state_verifier_session_handle: u32,
    state_verifier_session_capability:
        Zeroizing<[u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
    verified_reservation_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability:
        Zeroizing<[u8; FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
    verified_finality_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability:
        Zeroizing<[u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
}

impl PendingTargetReleaseGenerationSource {
    fn descriptor(
        &self,
        role_ordinal: usize,
    ) -> Result<&StreamDescriptor, TargetReleaseRuntimeError> {
        self.role_stream_descriptors
            .get(role_ordinal)
            .ok_or(TargetReleaseRuntimeError::InvalidInput)
    }

    fn read_chunk(
        &mut self,
        role_ordinal: usize,
        chunk_index: usize,
        output: &mut [u8],
    ) -> Result<(), TargetReleaseRuntimeError> {
        if role_ordinal != self.next_role_ordinal
            || chunk_index != self.next_chunk_index
            || output.is_empty()
        {
            return Err(TargetReleaseRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        let descriptor = self.descriptor(role_ordinal)?;
        let chunk_count = descriptor.ordered_chunk_digests.len();
        if chunk_index >= chunk_count {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let chunk_byte_length = FOUNDATION_PROFILE.stream_chunk_byte_length;
        let byte_start = chunk_index
            .checked_mul(chunk_byte_length)
            .ok_or(TargetReleaseRuntimeError::InvalidInput)?;
        let total_byte_length = usize::try_from(descriptor.total_byte_length)
            .map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        let byte_end = byte_start
            .checked_add(chunk_byte_length)
            .map(|end| end.min(total_byte_length))
            .ok_or(TargetReleaseRuntimeError::InvalidInput)?;
        if byte_start >= byte_end || output.len() != byte_end - byte_start {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let stream = self
            .role_streams
            .get(role_ordinal)
            .and_then(Option::as_ref)
            .ok_or(TargetReleaseRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ))?;
        output.copy_from_slice(&stream.canonical_bytes()[byte_start..byte_end]);
        self.next_chunk_index += 1;
        if self.next_chunk_index == chunk_count {
            self.role_streams[role_ordinal].take();
            self.next_role_ordinal += 1;
            self.next_chunk_index = 0;
        }
        Ok(())
    }

    const fn all_role_streams_read(&self) -> bool {
        self.next_role_ordinal == TARGET_ROLE_COUNT
    }
}

struct TargetReleaseVerificationTerminalSource {
    accepted_setup_authority_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability:
        Zeroizing<[u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
    verified_reservation_handle: u32,
    verified_output_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability:
        Zeroizing<[u8; FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH]>,
    verified_finality_handle: u32,
    target_pair: KllpsTargetPair,
    target_identifier_partial_bytes: Vec<u8>,
    target_order_partial_bytes: Vec<u8>,
}

thread_local! {
    static TARGET_RELEASE_GENERATION_SOURCE_REGISTRY:
        RefCell<SingleActiveTargetReleaseRegistry<PendingTargetReleaseGenerationSource>> =
        RefCell::new(SingleActiveTargetReleaseRegistry::default());
    static TARGET_RELEASE_VERIFICATION_TERMINAL_SOURCE_REGISTRY:
        RefCell<SingleActiveTargetReleaseRegistry<TargetReleaseVerificationTerminalSource>> =
        RefCell::new(SingleActiveTargetReleaseRegistry::default());
    static VERIFIED_TARGET_SHARE_REGISTRY: RefCell<BoundedVerifiedTargetShareRegistry> =
        RefCell::new(BoundedVerifiedTargetShareRegistry::default());
    static RECONSTRUCTED_TARGET_PAIR_REGISTRY: RefCell<ReconstructedTargetPairRegistry> =
        RefCell::new(ReconstructedTargetPairRegistry::default());
}

struct SelectedTargetReleaseRuntimePlan {
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
    proof_query_count: u32,
}

fn selected_target_release_runtime_plan(
    canonical_application_statement_bytes: &[u8],
) -> Result<SelectedTargetReleaseRuntimePlan, TargetReleaseRuntimeError> {
    let schema_identifier =
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(schema_identifier).ok_or(
        TargetReleaseRuntimeError::Relation(RelationPlanError::InvalidDomain),
    )?;
    let compilation = selected_target_release_relation()?;
    let relation_variant = compilation.relation_plan().select_variant(None, None)?;
    let limits = selected_proof_runtime_limits(
        schema_identifier,
        canonical_application_statement_bytes,
        relation_variant,
    )?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        compilation.relation_plan(),
        &relation_context,
        None,
        None,
    )?;
    let proof_query_count = relation_plan.proof_query_count()?;
    Ok(SelectedTargetReleaseRuntimePlan {
        relation_plan,
        limits,
        proof_query_count,
    })
}

fn resolve_single_board_source(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    verified_object_handle: u32,
) -> Result<VerifiedBoardApplicationSource, TargetReleaseRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(TargetReleaseRuntimeError::InvalidInput);
    }
    let mut sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[verified_object_handle],
    )
    .map_err(TargetReleaseRuntimeError::BoardRuntime)?;
    let source = sources.pop().ok_or(TargetReleaseRuntimeError::Refusal(
        RefusalReason::MissingPrerequisite,
    ))?;
    if !sources.is_empty() {
        return Err(TargetReleaseRuntimeError::InvalidInput);
    }
    Ok(source)
}

fn resolve_verified_target_pair(
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability: &[u8],
    verified_finality_handle: u32,
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
) -> Result<KllpsTargetPair, TargetReleaseRuntimeError> {
    with_verified_state_reservation(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
        |state_verifier, verified_reservation| {
            with_verified_finality(
                finality_verifier_session_handle,
                finality_verifier_session_capability,
                verified_finality_handle,
                |verified_finality| {
                    verify_finalized_kllps_target_pair(
                        state_verifier,
                        verified_finality,
                        verified_reservation,
                        target_identifier_bytes,
                        target_order_bytes,
                    )
                    .into_result()
                    .map_err(refusal_status)
                },
            )
        },
    )
    .map_err(TargetReleaseRuntimeError::AuthorityRuntime)
}

fn target_release_application_slot(
    accepted_setup_authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
    target_pair: &KllpsTargetPair,
) -> Result<(ProofApplicationSlot, u16), TargetReleaseRuntimeError> {
    let participant_binding = target_pair.participant_binding();
    let roster_position = with_verified_accepted_setup_authority(
        accepted_setup_authority_handle,
        |accepted_setup_authority| {
            accepted_setup_authority
                .participant_release_material(participant_binding.subject_participant_id)
                .map(|participant_material| participant_material.roster_position())
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "accepted setup has no release material for the reserved participant",
                    )
                })
        },
    )?;
    let binding = target_pair.binding();
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(binding.suite_id),
        Hash512::from_bytes(binding.ceremony_context_hash),
        Hash512::from_bytes(binding.action_context_hash),
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        Some(roster_position),
        None,
        None,
    )?;
    Ok((application_slot, roster_position))
}

fn prepare_target_release_witness(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
    action_private_randomness: &Rc<crate::foundation::ActionPrivateRandomness>,
    target_pair: &KllpsTargetPair,
    application_slot: ProofApplicationSlot,
) -> Result<KllpsTargetReleaseWitnessSource, TargetReleaseRuntimeError> {
    let authorized_partial =
        with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
            generate_authorized_factor_four_paired_partial_decryption(
                selected_suite,
                accepted_setup_authority_handle,
                action_private_randomness.as_ref(),
                target_pair,
                application_slot,
            )
        })
        .map_err(TargetReleaseRuntimeError::Runtime)??;
    lease_authorized_target_release_witness_source(
        accepted_setup_authority_handle,
        target_pair,
        authorized_partial,
    )
    .map_err(TargetReleaseRuntimeError::Canonical)
}

fn require_reservation_intent_source(
    source: &VerifiedBoardApplicationSource,
    target_pair: &KllpsTargetPair,
    roster_position: u16,
) -> Result<(), TargetReleaseRuntimeError> {
    let binding = target_pair.binding();
    let participant_binding = target_pair.participant_binding();
    if source.object_type() != FoundationObjectType::StateReservation
        || source.suite_identifier().into_bytes() != binding.suite_id
        || source.ceremony_context_hash().into_bytes() != binding.ceremony_context_hash
        || source.action_context_hash().into_bytes() != binding.action_context_hash
        || source.roster_hash().into_bytes() != binding.roster_hash
        || source.object_hash().into_bytes() != participant_binding.reservation_intent_object_hash
        || source
            .producer_participant_identity()
            .map(ParticipantIdentity::into_bytes)
            != Some(participant_binding.subject_participant_id)
        || source.producer_roster_position() != Some(roster_position)
        || source.producer_sequence() != 0
    {
        return Err(TargetReleaseRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_target_release_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    reservation_intent_source: &VerifiedBoardApplicationSource,
    witness_source: &KllpsTargetReleaseWitnessSource,
    runtime_plan: &SelectedTargetReleaseRuntimePlan,
    checkpoint_continuation: crate::foundation::AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedActionProofAttemptSource, TargetReleaseRuntimeError> {
    let proof_byte_length = u64::try_from(runtime_plan.limits.proof_byte_length())
        .map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
    resolve_prepared_action_proof_attempt_source(
        action_randomness_handle,
        verified_reservation_binding,
        reservation_intent_source,
        witness_source.application_slot(),
        Hash512::from_bytes(witness_source.application_statement_hash()),
        proof_byte_length,
        runtime_plan.proof_query_count,
        checkpoint_continuation,
    )
    .map_err(TargetReleaseRuntimeError::ActionRandomnessRuntime)
}

fn prepare_target_release_common_generation(
    witness_source: KllpsTargetReleaseWitnessSource,
    action_private_randomness: Rc<crate::foundation::ActionPrivateRandomness>,
    prepared_attempt: PreparedActionProofAttemptSource,
    limits: CommonProofRuntimeLimits,
) -> Result<
    (
        PreparedCommonProofGeneration,
        KllpsPartialDecryptionRoleStream,
        KllpsPartialDecryptionRoleStream,
    ),
    TargetReleaseRuntimeError,
> {
    Ok(witness_source
        .prepare_common_generation(action_private_randomness, prepared_attempt, limits)?
        .into_parts())
}

fn resumed_generation_preparation_error(
    error: TargetReleaseRuntimeError,
) -> CommonProofGenerationPreparationError {
    match error {
        TargetReleaseRuntimeError::Runtime(error) => {
            CommonProofGenerationPreparationError::Runtime(error)
        }
        TargetReleaseRuntimeError::GenerationPreparation(
            KllpsTargetReleaseGenerationPreparationError::Proof(error),
        ) => error,
        TargetReleaseRuntimeError::GenerationPreparation(
            KllpsTargetReleaseGenerationPreparationError::Runtime(error),
        ) => CommonProofGenerationPreparationError::Runtime(error),
        _ => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding,
        ),
    }
}

#[derive(Clone, Copy)]
enum TargetReleaseGenerationMode {
    Fresh,
    Resume,
}

#[allow(clippy::too_many_arguments)]
fn prepare_target_release_generation(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    verified_reservation_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability: [u8; FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    verified_finality_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: [u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    reservation_intent_object_handle: u32,
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
    checkpoint_lineage_identifier: [u8; CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH],
    generation_mode: TargetReleaseGenerationMode,
) -> Result<(u32, u32), TargetReleaseRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH] {
        return Err(TargetReleaseRuntimeError::InvalidInput);
    }
    let target_pair = resolve_verified_target_pair(
        state_verifier_session_handle,
        &state_verifier_session_capability,
        verified_reservation_handle,
        finality_verifier_session_handle,
        &finality_verifier_session_capability,
        verified_finality_handle,
        target_identifier_bytes,
        target_order_bytes,
    )?;
    let accepted_setup_authority =
        VerifiedAcceptedSetupAuthorityHandle::from_identifier(accepted_setup_authority_handle);
    let (application_slot, roster_position) =
        target_release_application_slot(&accepted_setup_authority, &target_pair)?;
    let action_private_randomness =
        retain_action_private_randomness_for_exact_family(action_randomness_handle)
            .map_err(TargetReleaseRuntimeError::ActionRandomnessRuntime)?;
    let witness_source = prepare_target_release_witness(
        selected_suite_handle,
        &accepted_setup_authority,
        &action_private_randomness,
        &target_pair,
        application_slot,
    )?;
    let canonical_application_statement_bytes = witness_source
        .canonical_application_statement_bytes()
        .to_vec();
    let runtime_plan =
        selected_target_release_runtime_plan(&canonical_application_statement_bytes)?;
    let checkpoint_schedule_digest = runtime_plan
        .relation_plan
        .checkpoint_schedule_digest(runtime_plan.limits)?;
    let reservation_intent_source = resolve_single_board_source(
        board_verifier_session_handle,
        &board_verifier_session_capability,
        reservation_intent_object_handle,
    )?;
    require_reservation_intent_source(&reservation_intent_source, &target_pair, roster_position)?;
    let verified_reservation_binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        &state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(TargetReleaseRuntimeError::AuthorityRuntime)?;
    if verified_reservation_binding.authorization_hash.into_bytes()
        != target_pair.binding().authorization_hash
    {
        return Err(TargetReleaseRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    let fresh_continuation =
        crate::foundation::AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let prepared_attempt = resolve_target_release_prepared_attempt(
        action_randomness_handle,
        verified_reservation_binding,
        &reservation_intent_source,
        &witness_source,
        &runtime_plan,
        fresh_continuation,
    )?;
    let (initial_common_generation, target_identifier_stream, target_order_stream) =
        prepare_target_release_common_generation(
            witness_source,
            Rc::clone(&action_private_randomness),
            prepared_attempt,
            runtime_plan.limits,
        )?;
    let target_identifier_descriptor = target_identifier_stream.descriptor()?;
    let target_order_descriptor = target_order_stream.descriptor()?;
    let release_binding = target_pair.binding().clone();
    let participant_binding = target_pair.participant_binding().clone();

    let generation_family_adapter = match generation_mode {
        TargetReleaseGenerationMode::Fresh => {
            CommonProofGenerationFamilyAdapter::fresh(initial_common_generation)
        }
        TargetReleaseGenerationMode::Resume => {
            let description = CommonProofGenerationFamilyAdapterDescription::new(
                initial_common_generation.runtime_binding_hash(),
                initial_common_generation.generation_authorization_hash(),
                initial_common_generation.proof_attempt_lineage_identifier(),
            );
            drop(initial_common_generation);
            let expected_statement = canonical_application_statement_bytes.clone();
            let expected_target_identifier_descriptor = target_identifier_descriptor.clone();
            let expected_target_order_descriptor = target_order_descriptor.clone();
            let resumed_reservation_intent_source = reservation_intent_source.clone();
            let resumed_action_private_randomness = Rc::clone(&action_private_randomness);
            CommonProofGenerationFamilyAdapter::resume(
                description,
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
                Box::new(move |authenticated_continuation| {
                    let accepted_setup_authority =
                        VerifiedAcceptedSetupAuthorityHandle::from_identifier(
                            accepted_setup_authority_handle,
                        );
                    let witness_source = prepare_target_release_witness(
                        selected_suite_handle,
                        &accepted_setup_authority,
                        &resumed_action_private_randomness,
                        &target_pair,
                        application_slot,
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    if witness_source.canonical_application_statement_bytes() != expected_statement
                    {
                        return Err(CommonProofGenerationPreparationError::Runtime(
                            CommonProofRuntimeError::WrongVerificationBinding,
                        ));
                    }
                    let resumed_runtime_plan = selected_target_release_runtime_plan(
                        witness_source.canonical_application_statement_bytes(),
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    if resumed_runtime_plan
                        .relation_plan
                        .checkpoint_schedule_digest(resumed_runtime_plan.limits)
                        .map_err(CommonProofGenerationPreparationError::Runtime)?
                        != checkpoint_schedule_digest
                    {
                        return Err(CommonProofGenerationPreparationError::Runtime(
                            CommonProofRuntimeError::WrongVerificationBinding,
                        ));
                    }
                    let prepared_attempt = resolve_target_release_prepared_attempt(
                        action_randomness_handle,
                        verified_reservation_binding,
                        &resumed_reservation_intent_source,
                        &witness_source,
                        &resumed_runtime_plan,
                        authenticated_continuation,
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    let (common_generation, target_identifier, target_order) =
                        prepare_target_release_common_generation(
                            witness_source,
                            Rc::clone(&resumed_action_private_randomness),
                            prepared_attempt,
                            resumed_runtime_plan.limits,
                        )
                        .map_err(resumed_generation_preparation_error)?;
                    if target_identifier.descriptor().map_err(|_| {
                        CommonProofGenerationPreparationError::Runtime(
                            CommonProofRuntimeError::WrongVerificationBinding,
                        )
                    })? != expected_target_identifier_descriptor
                        || target_order.descriptor().map_err(|_| {
                            CommonProofGenerationPreparationError::Runtime(
                                CommonProofRuntimeError::WrongVerificationBinding,
                            )
                        })? != expected_target_order_descriptor
                    {
                        return Err(CommonProofGenerationPreparationError::Runtime(
                            CommonProofRuntimeError::WrongVerificationBinding,
                        ));
                    }
                    Ok(common_generation)
                }),
            )
        }
    };

    let generation_source = PendingTargetReleaseGenerationSource {
        release_binding,
        participant_binding,
        roster_position,
        canonical_application_statement_bytes,
        role_stream_descriptors: [target_identifier_descriptor, target_order_descriptor],
        role_streams: [Some(target_identifier_stream), Some(target_order_stream)],
        next_role_ordinal: 0,
        next_chunk_index: 0,
        state_verifier_session_handle,
        state_verifier_session_capability: Zeroizing::new(state_verifier_session_capability),
        verified_reservation_handle,
        finality_verifier_session_handle,
        finality_verifier_session_capability: Zeroizing::new(finality_verifier_session_capability),
        verified_finality_handle,
        board_verifier_session_handle,
        board_verifier_session_capability: Zeroizing::new(board_verifier_session_capability),
    };
    let generation_source_handle = TARGET_RELEASE_GENERATION_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().retain(generation_source))?;
    match retain_common_proof_generation_family_adapter(generation_family_adapter) {
        Ok(adapter_handle) => Ok((adapter_handle, generation_source_handle)),
        Err(error) => {
            TARGET_RELEASE_GENERATION_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(generation_source_handle))?;
            Err(TargetReleaseRuntimeError::Runtime(error))
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn require_state_output_matches_release(
    state_verifier: &StateVerifier,
    verified_reservation: &VerifiedStateReservation,
    verified_output: &VerifiedStateOutput,
    verified_finality: &VerifiedFinality,
    target_share_source: &VerifiedBoardApplicationSource,
    release_binding: &KllpsReleaseBinding,
    participant_binding: &KllpsParticipantReleaseBinding,
    roster_position: u16,
    role_stream_descriptors: &[StreamDescriptor; TARGET_ROLE_COUNT],
) -> Result<(), RefusalReason> {
    let finality_statement = verified_finality.statement();
    if state_verifier
        .roster_hash()
        .map_err(|error| error.refusal_reason)?
        .into_bytes()
        != release_binding.roster_hash
        || finality_statement.suite_identifier().into_bytes() != release_binding.suite_id
        || finality_statement.ceremony_context_hash().into_bytes()
            != release_binding.ceremony_context_hash
        || finality_statement.action_context_hash().into_bytes()
            != release_binding.action_context_hash
        || finality_statement.roster_hash().into_bytes() != release_binding.roster_hash
        || verified_finality.finality_hash().into_bytes() != release_binding.finality_hash
        || verified_finality.verified_setup_source_hash().into_bytes()
            != release_binding.verified_setup_source_hash
        || verified_finality
            .target_release_authorization_hash()
            .map_err(|error| error.refusal_reason)?
            .into_bytes()
            != release_binding.authorization_hash
        || verified_finality
            .target_identifier_full_object_digest()
            .into_bytes()
            != release_binding.target_identifier_full_digest
        || verified_finality
            .target_order_full_object_digest()
            .into_bytes()
            != release_binding.target_order_full_digest
        || verified_reservation.capability_kind() != StateCapabilityKind::TargetRelease
        || verified_reservation.suite_id().into_bytes() != release_binding.suite_id
        || verified_reservation.ceremony_context_hash().into_bytes()
            != release_binding.ceremony_context_hash
        || verified_reservation.action_context_hash().into_bytes()
            != release_binding.action_context_hash
        || verified_reservation.intent_object_hash().into_bytes()
            != participant_binding.reservation_intent_object_hash
        || verified_reservation.subject_participant_id().into_bytes()
            != participant_binding.subject_participant_id
        || verified_reservation.state_key().into_bytes() != participant_binding.state_key
        || verified_reservation.authorization_hash().into_bytes()
            != release_binding.authorization_hash
        || verified_output.capability_kind() != verified_reservation.capability_kind()
        || verified_output.suite_id() != verified_reservation.suite_id()
        || verified_output.ceremony_context_hash() != verified_reservation.ceremony_context_hash()
        || verified_output.action_context_hash() != verified_reservation.action_context_hash()
        || verified_output.reservation_intent_object_hash()
            != verified_reservation.intent_object_hash()
        || verified_output.subject_participant_id() != verified_reservation.subject_participant_id()
        || verified_output.state_key() != verified_reservation.state_key()
        || verified_output.authorization_hash() != verified_reservation.authorization_hash()
    {
        return Err(RefusalReason::WrongContext);
    }
    let output_bundle = verified_output
        .target_release_output_bundle()
        .ok_or(RefusalReason::MissingPrerequisite)?;
    if output_bundle.finality_hash().into_bytes() != release_binding.finality_hash
        || output_bundle.reservation_intent_object_hash().into_bytes()
            != participant_binding.reservation_intent_object_hash
        || output_bundle.target_identifier_descriptor() != &role_stream_descriptors[0]
        || output_bundle.target_order_descriptor() != &role_stream_descriptors[1]
        || target_share_source.object_type() != FoundationObjectType::TargetDecryptionShare
        || target_share_source.suite_identifier().into_bytes() != release_binding.suite_id
        || target_share_source.ceremony_context_hash().into_bytes()
            != release_binding.ceremony_context_hash
        || target_share_source.action_context_hash().into_bytes()
            != release_binding.action_context_hash
        || target_share_source.roster_hash().into_bytes() != release_binding.roster_hash
        || target_share_source.object_hash() != verified_output.output_intent_object_hash()
        || target_share_source
            .producer_participant_identity()
            .map(ParticipantIdentity::into_bytes)
            != Some(participant_binding.subject_participant_id)
        || target_share_source.producer_roster_position() != Some(roster_position)
        || target_share_source.producer_sequence() != 0
    {
        return Err(RefusalReason::WrongHashOrRoot);
    }
    Ok(())
}

fn bind_generated_target_release_proof(
    generated_common_proof_handle: u32,
    generation_source_handle: u32,
    verified_output_handle: u32,
    target_share_object_handle: u32,
) -> Result<(), TargetReleaseRuntimeError> {
    let generation_source = TARGET_RELEASE_GENERATION_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(generation_source_handle))?;
    let result = (|| {
        if !generation_source.all_role_streams_read() {
            return Err(TargetReleaseRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        let target_share_source = resolve_single_board_source(
            generation_source.board_verifier_session_handle,
            &generation_source.board_verifier_session_capability[..],
            target_share_object_handle,
        )?;
        with_verified_state_reservation_and_output(
            generation_source.state_verifier_session_handle,
            &generation_source.state_verifier_session_capability[..],
            generation_source.verified_reservation_handle,
            verified_output_handle,
            |state_verifier, verified_reservation, verified_output| {
                with_verified_finality(
                    generation_source.finality_verifier_session_handle,
                    &generation_source.finality_verifier_session_capability[..],
                    generation_source.verified_finality_handle,
                    |verified_finality| {
                        require_state_output_matches_release(
                            state_verifier,
                            verified_reservation,
                            verified_output,
                            verified_finality,
                            &target_share_source,
                            &generation_source.release_binding,
                            &generation_source.participant_binding,
                            generation_source.roster_position,
                            &generation_source.role_stream_descriptors,
                        )
                        .map_err(refusal_status)
                    },
                )
            },
        )
        .map_err(TargetReleaseRuntimeError::AuthorityRuntime)?;
        let proof_descriptor = with_verified_state_reservation_and_output(
            generation_source.state_verifier_session_handle,
            &generation_source.state_verifier_session_capability[..],
            generation_source.verified_reservation_handle,
            verified_output_handle,
            |_state_verifier, _verified_reservation, verified_output| {
                verified_output
                    .target_release_output_bundle()
                    .map(|bundle| bundle.malicious_share_proof_descriptor().clone())
                    .ok_or_else(|| refusal_status(RefusalReason::MissingPrerequisite))
            },
        )
        .map_err(TargetReleaseRuntimeError::AuthorityRuntime)?;
        bind_generated_common_proof_to_verified_board_source(
            generated_common_proof_handle,
            &target_share_source,
            &proof_descriptor,
            &generation_source.canonical_application_statement_bytes,
        )?;
        Ok(())
    })();
    if result.is_err() {
        TARGET_RELEASE_GENERATION_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .restore(generation_source_handle, generation_source)
        })?;
    }
    result
}

struct VerifiedTargetReleaseOutputAuthority {
    target_identifier_descriptor: StreamDescriptor,
    target_order_descriptor: StreamDescriptor,
    malicious_share_proof_descriptor: StreamDescriptor,
    roster_position: u16,
}

fn resolve_verified_target_release_output_authority(
    accepted_setup_authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    verified_output_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability: &[u8],
    verified_finality_handle: u32,
    target_share_source: &VerifiedBoardApplicationSource,
    target_pair: &KllpsTargetPair,
) -> Result<VerifiedTargetReleaseOutputAuthority, TargetReleaseRuntimeError> {
    let roster_position =
        target_release_application_slot(accepted_setup_authority_handle, target_pair)?.1;
    with_verified_state_reservation_and_output(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
        verified_output_handle,
        |state_verifier, verified_reservation, verified_output| {
            with_verified_finality(
                finality_verifier_session_handle,
                finality_verifier_session_capability,
                verified_finality_handle,
                |verified_finality| {
                    let output_bundle = verified_output
                        .target_release_output_bundle()
                        .ok_or_else(|| refusal_status(RefusalReason::MissingPrerequisite))?;
                    let role_stream_descriptors = [
                        output_bundle.target_identifier_descriptor().clone(),
                        output_bundle.target_order_descriptor().clone(),
                    ];
                    require_state_output_matches_release(
                        state_verifier,
                        verified_reservation,
                        verified_output,
                        verified_finality,
                        target_share_source,
                        target_pair.binding(),
                        target_pair.participant_binding(),
                        roster_position,
                        &role_stream_descriptors,
                    )
                    .map_err(refusal_status)?;
                    Ok(VerifiedTargetReleaseOutputAuthority {
                        target_identifier_descriptor: output_bundle
                            .target_identifier_descriptor()
                            .clone(),
                        target_order_descriptor: output_bundle.target_order_descriptor().clone(),
                        malicious_share_proof_descriptor: output_bundle
                            .malicious_share_proof_descriptor()
                            .clone(),
                        roster_position,
                    })
                },
            )
        },
    )
    .map_err(TargetReleaseRuntimeError::AuthorityRuntime)
}

#[allow(clippy::too_many_arguments)]
fn prepare_target_release_verification(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: [u8; STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    verified_reservation_handle: u32,
    verified_output_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability: [u8; FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    verified_finality_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: [u8; BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH],
    target_share_object_handle: u32,
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
    target_identifier_partial_bytes: &[u8],
    target_order_partial_bytes: &[u8],
) -> Result<(u32, u32), TargetReleaseRuntimeError> {
    if target_identifier_partial_bytes.is_empty()
        || target_order_partial_bytes.is_empty()
        || target_identifier_partial_bytes.len()
            > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
        || target_order_partial_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(TargetReleaseRuntimeError::InvalidInput);
    }
    let target_pair = resolve_verified_target_pair(
        state_verifier_session_handle,
        &state_verifier_session_capability,
        verified_reservation_handle,
        finality_verifier_session_handle,
        &finality_verifier_session_capability,
        verified_finality_handle,
        target_identifier_bytes,
        target_order_bytes,
    )?;
    let target_share_source = resolve_single_board_source(
        board_verifier_session_handle,
        &board_verifier_session_capability,
        target_share_object_handle,
    )?;
    let accepted_setup_authority =
        VerifiedAcceptedSetupAuthorityHandle::from_identifier(accepted_setup_authority_handle);
    let output_authority = resolve_verified_target_release_output_authority(
        &accepted_setup_authority,
        state_verifier_session_handle,
        &state_verifier_session_capability,
        verified_reservation_handle,
        verified_output_handle,
        finality_verifier_session_handle,
        &finality_verifier_session_capability,
        verified_finality_handle,
        &target_share_source,
        &target_pair,
    )?;
    let participant_binding = target_pair.participant_binding();
    let release_binding = target_pair.binding();
    let accepted_share_lease = lease_verified_participant_target_release_source(
        &accepted_setup_authority,
        participant_binding.subject_participant_id,
    )?;
    if accepted_share_lease.roster_position() != output_authority.roster_position {
        return Err(TargetReleaseRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    let accepted_roots = with_verified_accepted_setup_authority(
        &accepted_setup_authority,
        |accepted_setup_authority| {
            accepted_setup_authority
                .participant_release_material(participant_binding.subject_participant_id)
                .map(|participant_material| {
                    participant_material
                        .ordered_aggregate_threshold_roots()
                        .to_vec()
                })
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::ComponentMismatch,
                        "accepted setup has no release roots for the target-share subject",
                    )
                })
        },
    )?;
    let canonical_application_statement_bytes = canonical_selected_target_share_statement(
        FOUNDATION_PROFILE.protocol_version,
        release_binding.suite_id,
        release_binding.ceremony_context_hash,
        release_binding.action_context_hash,
        release_binding.roster_hash,
        release_binding.verified_setup_source_hash,
        release_binding.finality_hash,
        participant_binding.reservation_intent_object_hash,
        participant_binding.subject_participant_id,
        output_authority.roster_position,
        &accepted_roots,
        &output_authority.target_identifier_descriptor,
        &output_authority.target_order_descriptor,
    )
    .map_err(|error| {
        TargetReleaseRuntimeError::Refusal(match error {
            SelectedApplicationStatementError::CanonicalEncoding => {
                RefusalReason::MalformedEncoding
            }
            SelectedApplicationStatementError::WrongSchema
            | SelectedApplicationStatementError::WrongValue => RefusalReason::WrongContext,
            SelectedApplicationStatementError::WrongTypeOrLength => {
                RefusalReason::WrongTypeOrLength
            }
            SelectedApplicationStatementError::InvalidProfile
            | SelectedApplicationStatementError::CountOverflow => {
                RefusalReason::OutsideSupportedProfile
            }
        })
    })?;
    let runtime_plan =
        selected_target_release_runtime_plan(&canonical_application_statement_bytes)?;
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || selected_suite.suite_identifier() != release_binding.suite_id
        {
            return Err(TargetReleaseRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(TargetReleaseRuntimeError::Runtime)??;
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(release_binding.suite_id),
        Hash512::from_bytes(release_binding.ceremony_context_hash),
        Hash512::from_bytes(release_binding.action_context_hash),
        ProofApplicationSlotCeilings::TARGET_SHARE_PROOF_STATEMENT_SCHEMA_IDENTIFIER,
        Some(output_authority.roster_position),
        None,
        None,
    )?;
    let proof_header = ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.clone(),
        &CanonicalDecodeLimits::default(),
    )?;
    let proof_application_binding = ProofApplicationBinding::new(
        application_slot,
        proof_header.proof_header_hash()?,
        output_authority.malicious_share_proof_descriptor,
    )?;
    let statement_source =
        VerifiedCommonProofStatementSource::from_exact_family_verified_board_source(
            target_share_source,
            FOUNDATION_PROFILE.protocol_version,
            canonical_application_statement_bytes,
            proof_application_binding,
            runtime_plan.relation_plan,
            runtime_plan.limits,
        )?;
    let statement_trees = VerifiedStatementOwnedTree::from_verified_target_release_source(
        &statement_source,
        &accepted_share_lease,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let verified_column_evaluator = verified_target_release_column_evaluator(
        &target_pair,
        usize::from(output_authority.roster_position),
        target_identifier_partial_bytes,
        target_order_partial_bytes,
    )?;
    let terminal_source = TargetReleaseVerificationTerminalSource {
        accepted_setup_authority_handle,
        state_verifier_session_handle,
        state_verifier_session_capability: Zeroizing::new(state_verifier_session_capability),
        verified_reservation_handle,
        verified_output_handle,
        finality_verifier_session_handle,
        finality_verifier_session_capability: Zeroizing::new(finality_verifier_session_capability),
        verified_finality_handle,
        target_pair,
        target_identifier_partial_bytes: target_identifier_partial_bytes.to_vec(),
        target_order_partial_bytes: target_order_partial_bytes.to_vec(),
    };
    let terminal_source_handle = TARGET_RELEASE_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().retain(terminal_source))?;
    let selected_suite_handle =
        CommonProofSelectedSuiteCapabilityHandle::from_identifier(selected_suite_handle);
    let adapter_result =
        retain_common_proof_verification_family_adapter_from_upstream(move |upstream_inputs| {
            upstream_inputs.prepare_statement_tree_family_verification(
                &selected_suite_handle,
                statement_source,
                statement_trees,
                Box::new(verified_column_evaluator),
            )
        });
    match adapter_result {
        Ok(adapter_handle) => Ok((adapter_handle, terminal_source_handle)),
        Err(error) => {
            TARGET_RELEASE_VERIFICATION_TERMINAL_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
            Err(TargetReleaseRuntimeError::Runtime(error))
        }
    }
}

fn preflight_verified_target_share(
    verified_common_proof: super::BorrowedVerifiedCommonProofCapability<'_>,
    terminal_source: &TargetReleaseVerificationTerminalSource,
) -> Result<VerifiedKllpsPairedSharePreflight, CommonProofRuntimeError> {
    with_verified_state_reservation_and_output(
        terminal_source.state_verifier_session_handle,
        &terminal_source.state_verifier_session_capability[..],
        terminal_source.verified_reservation_handle,
        terminal_source.verified_output_handle,
        |_state_verifier, verified_reservation, verified_output| {
            with_verified_finality(
                terminal_source.finality_verifier_session_handle,
                &terminal_source.finality_verifier_session_capability[..],
                terminal_source.verified_finality_handle,
                |verified_finality| {
                    let accepted_setup_authority =
                        VerifiedAcceptedSetupAuthorityHandle::from_identifier(
                            terminal_source.accepted_setup_authority_handle,
                        );
                    with_verified_accepted_setup_authority(
                        &accepted_setup_authority,
                        |accepted_setup_authority| {
                            preflight_kllps_paired_share_from_borrowed_common_proof(
                                verified_common_proof,
                                KllpsShareVerificationSources {
                                    accepted_setup_authority,
                                    verified_finality,
                                    verified_reservation,
                                    verified_output,
                                    target_pair: &terminal_source.target_pair,
                                    target_identifier_partial_bytes: &terminal_source
                                        .target_identifier_partial_bytes,
                                    target_order_partial_bytes: &terminal_source
                                        .target_order_partial_bytes,
                                },
                            )
                        },
                    )
                    .map_err(|_| refusal_status(RefusalReason::WrongHashOrRoot))
                },
            )
        },
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
}

fn finish_target_release_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<u32, CommonProofRuntimeError> {
    let terminal_source = TARGET_RELEASE_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
    let reserved_share_handle =
        match VERIFIED_TARGET_SHARE_REGISTRY.with(|registry| registry.borrow_mut().reserve()) {
            Ok(handle) => handle,
            Err(error) => {
                TARGET_RELEASE_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                    registry
                        .borrow_mut()
                        .restore(terminal_source_handle, terminal_source)
                })?;
                return Err(error);
            }
        };
    let terminal_source_cell = RefCell::new(Some(terminal_source));
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_common_proof| {
            let terminal_source = terminal_source_cell.borrow();
            let terminal_source = terminal_source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            preflight_verified_target_share(verified_common_proof, terminal_source)
        },
        |verified_common_proof, share_preflight| {
            let _terminal_source = terminal_source_cell
                .borrow_mut()
                .take()
                .expect("target-share preflight retained the exact terminal source");
            let verified_share = share_preflight.complete(verified_common_proof);
            VERIFIED_TARGET_SHARE_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .commit_preflighted(reserved_share_handle, verified_share)
            })
        },
    );
    if result.is_err() {
        VERIFIED_TARGET_SHARE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .release_reservation(reserved_share_handle)
        })?;
        if let Some(terminal_source) = terminal_source_cell.into_inner() {
            TARGET_RELEASE_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .restore(terminal_source_handle, terminal_source)
            })?;
        }
    }
    result
}

fn decode_verified_target_share_handles(
    canonical_handle_bytes: &[u8],
) -> Result<[u32; KLLPS_RECONSTRUCTION_THRESHOLD], TargetReleaseRuntimeError> {
    let expected_byte_length = KLLPS_RECONSTRUCTION_THRESHOLD
        .checked_mul(HANDLE_BYTE_LENGTH)
        .ok_or(TargetReleaseRuntimeError::InvalidInput)?;
    if canonical_handle_bytes.len() != expected_byte_length {
        return Err(TargetReleaseRuntimeError::InvalidInput);
    }
    let mut handles = [0_u32; KLLPS_RECONSTRUCTION_THRESHOLD];
    for (handle, handle_bytes) in handles
        .iter_mut()
        .zip(canonical_handle_bytes.chunks_exact(HANDLE_BYTE_LENGTH))
    {
        let handle_bytes = <[u8; HANDLE_BYTE_LENGTH]>::try_from(handle_bytes)
            .map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        *handle = u32::from_le_bytes(handle_bytes);
    }
    Ok(handles)
}

fn reconstruct_verified_target_release_shares(
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability: &[u8],
    verified_finality_handle: u32,
    target_identifier_bytes: &[u8],
    target_order_bytes: &[u8],
    verified_share_handles: &[u32],
) -> Result<u32, TargetReleaseRuntimeError> {
    let reserved_target_pair_handle =
        RECONSTRUCTED_TARGET_PAIR_REGISTRY.with(|registry| registry.borrow_mut().reserve())?;
    let result = (|| {
        let target_pair = with_verified_finality(
            finality_verifier_session_handle,
            finality_verifier_session_capability,
            verified_finality_handle,
            |verified_finality| {
                verify_finalized_kllps_reconstruction_target_pair(
                    verified_finality,
                    target_identifier_bytes,
                    target_order_bytes,
                )
                .into_result()
                .map_err(refusal_status)
            },
        )
        .map_err(TargetReleaseRuntimeError::AuthorityRuntime)?;
        let pending_target_pair = VERIFIED_TARGET_SHARE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .reconstruct_and_consume(&target_pair, verified_share_handles)
        })?;
        Ok(RECONSTRUCTED_TARGET_PAIR_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .commit_reserved(reserved_target_pair_handle, pending_target_pair)
        }))
    })();
    if result.is_err() {
        RECONSTRUCTED_TARGET_PAIR_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .release_reservation(reserved_target_pair_handle)
        })?;
    }
    result
}

const fn refusal_status(reason: RefusalReason) -> u32 {
    reason.canonical_code() as u32
}

fn canonical_error_status(error: &CanonicalError) -> u32 {
    match error.code {
        CanonicalErrorCode::MalformedLength => refusal_status(RefusalReason::WrongTypeOrLength),
        CanonicalErrorCode::UnsupportedObjectVersion => {
            refusal_status(RefusalReason::UnsupportedVersionOrSuite)
        }
        CanonicalErrorCode::ComponentMismatch => refusal_status(RefusalReason::WrongHashOrRoot),
        CanonicalErrorCode::DuplicateField
        | CanonicalErrorCode::InvalidEnum
        | CanonicalErrorCode::InvalidProtocolObject
        | CanonicalErrorCode::InvalidHex
        | CanonicalErrorCode::InvalidUtf8
        | CanonicalErrorCode::MalformedMagic
        | CanonicalErrorCode::MalformedVarUint
        | CanonicalErrorCode::NonCanonicalVarUint
        | CanonicalErrorCode::TrailingBytes => refusal_status(RefusalReason::MalformedEncoding),
    }
}

fn runtime_error_status(error: TargetReleaseRuntimeError) -> u32 {
    match error {
        TargetReleaseRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        TargetReleaseRuntimeError::Canonical(error) => canonical_error_status(&error),
        TargetReleaseRuntimeError::Foundation(error) => refusal_status(error.refusal_reason),
        TargetReleaseRuntimeError::AuthorityRuntime(status)
        | TargetReleaseRuntimeError::ActionRandomnessRuntime(status)
        | TargetReleaseRuntimeError::BoardRuntime(status) => status,
        TargetReleaseRuntimeError::Refusal(reason) => refusal_status(reason),
        TargetReleaseRuntimeError::InvalidInput => refusal_status(RefusalReason::WrongTypeOrLength),
        TargetReleaseRuntimeError::GenerationPreparation(error) => match error {
            KllpsTargetReleaseGenerationPreparationError::Proof(error) => match error {
                CommonProofGenerationPreparationError::Runtime(error) => {
                    super::runtime_ffi::runtime_error_status(error)
                }
                CommonProofGenerationPreparationError::Generation(error) => {
                    let _ = error;
                    refusal_status(RefusalReason::InvalidProof)
                }
            },
            KllpsTargetReleaseGenerationPreparationError::Runtime(error) => {
                super::runtime_ffi::runtime_error_status(error)
            }
            KllpsTargetReleaseGenerationPreparationError::Prover(error) => {
                let _ = error;
                refusal_status(RefusalReason::InvalidArithmeticRelation)
            }
            KllpsTargetReleaseGenerationPreparationError::PrivateCoins(error) => {
                let _ = error;
                refusal_status(RefusalReason::WrongContext)
            }
            KllpsTargetReleaseGenerationPreparationError::Witness(error) => {
                let _ = error;
                refusal_status(RefusalReason::InvalidArithmeticRelation)
            }
        },
        TargetReleaseRuntimeError::Accounting(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        TargetReleaseRuntimeError::Profile(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        TargetReleaseRuntimeError::Relation(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        TargetReleaseRuntimeError::RelationCapability(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
    declared_byte_length: usize,
) -> Result<[u8; BYTE_LENGTH], TargetReleaseRuntimeError> {
    if pointer.is_null() || declared_byte_length != BYTE_LENGTH {
        return Err(TargetReleaseRuntimeError::InvalidInput);
    }
    unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) }
        .try_into()
        .map_err(|_| TargetReleaseRuntimeError::InvalidInput)
}

unsafe fn variable_input<'input>(
    pointer: *const u8,
    byte_length: usize,
) -> Result<&'input [u8], TargetReleaseRuntimeError> {
    if pointer.is_null()
        || byte_length == 0
        || byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(TargetReleaseRuntimeError::InvalidInput);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, byte_length) })
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_from_ffi_inputs(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability_pointer: *const u8,
    finality_verifier_session_capability_byte_length: usize,
    verified_finality_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    reservation_intent_object_handle: u32,
    target_identifier_pointer: *const u8,
    target_identifier_byte_length: usize,
    target_order_pointer: *const u8,
    target_order_byte_length: usize,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    generation_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: TargetReleaseGenerationMode,
) -> u32 {
    let result = (|| {
        if generation_source_handle_output_pointer.is_null() {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let state_verifier_session_capability = unsafe {
            fixed_input::<STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        }?;
        let finality_verifier_session_capability = unsafe {
            fixed_input::<FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                finality_verifier_session_capability_pointer,
                finality_verifier_session_capability_byte_length,
            )
        }?;
        let board_verifier_session_capability = unsafe {
            fixed_input::<BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        }?;
        let target_identifier_bytes =
            unsafe { variable_input(target_identifier_pointer, target_identifier_byte_length) }?;
        let target_order_bytes =
            unsafe { variable_input(target_order_pointer, target_order_byte_length) }?;
        let checkpoint_lineage_identifier = unsafe {
            fixed_input::<CHECKPOINT_LINEAGE_IDENTIFIER_BYTE_LENGTH>(
                checkpoint_lineage_identifier_pointer,
                checkpoint_lineage_identifier_byte_length,
            )
        }?;
        prepare_target_release_generation(
            selected_suite_handle,
            accepted_setup_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability,
            verified_reservation_handle,
            finality_verifier_session_handle,
            finality_verifier_session_capability,
            verified_finality_handle,
            board_verifier_session_handle,
            board_verifier_session_capability,
            reservation_intent_object_handle,
            target_identifier_bytes,
            target_order_bytes,
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

/// Retains a fresh target-share common-proof adapter and its one-pass paired
/// partial-decryption source. All cryptographic facts come from live worker
/// capabilities; the byte inputs provide only authenticated stream storage.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. The source and
/// non-null status outputs must each name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_prepare_generation(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability_pointer: *const u8,
    finality_verifier_session_capability_byte_length: usize,
    verified_finality_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    reservation_intent_object_handle: u32,
    target_identifier_pointer: *const u8,
    target_identifier_byte_length: usize,
    target_order_pointer: *const u8,
    target_order_byte_length: usize,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    generation_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_from_ffi_inputs(
            selected_suite_handle,
            accepted_setup_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            finality_verifier_session_handle,
            finality_verifier_session_capability_pointer,
            finality_verifier_session_capability_byte_length,
            verified_finality_handle,
            board_verifier_session_handle,
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
            reservation_intent_object_handle,
            target_identifier_pointer,
            target_identifier_byte_length,
            target_order_pointer,
            target_order_byte_length,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            generation_source_handle_output_pointer,
            status_pointer,
            TargetReleaseGenerationMode::Fresh,
        )
    }
}

/// Retains a resume adapter for the exact fresh target-share attempt. The
/// generic runtime invokes it only after authenticating checkpoint custody and
/// the selected checkpoint schedule.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. The source and
/// non-null status outputs must each name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_prepare_resumed_generation(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability_pointer: *const u8,
    finality_verifier_session_capability_byte_length: usize,
    verified_finality_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    reservation_intent_object_handle: u32,
    target_identifier_pointer: *const u8,
    target_identifier_byte_length: usize,
    target_order_pointer: *const u8,
    target_order_byte_length: usize,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    generation_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_from_ffi_inputs(
            selected_suite_handle,
            accepted_setup_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            state_verifier_session_capability_pointer,
            state_verifier_session_capability_byte_length,
            verified_reservation_handle,
            finality_verifier_session_handle,
            finality_verifier_session_capability_pointer,
            finality_verifier_session_capability_byte_length,
            verified_finality_handle,
            board_verifier_session_handle,
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
            reservation_intent_object_handle,
            target_identifier_pointer,
            target_identifier_byte_length,
            target_order_pointer,
            target_order_byte_length,
            checkpoint_lineage_identifier_pointer,
            checkpoint_lineage_identifier_byte_length,
            generation_source_handle_output_pointer,
            status_pointer,
            TargetReleaseGenerationMode::Resume,
        )
    }
}

/// Returns the canonical descriptor encoding length for one fixed target role.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_partial_descriptor_byte_length(
    generation_source_handle: u32,
    role_ordinal: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        let role_ordinal =
            usize::try_from(role_ordinal).map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        TARGET_RELEASE_GENERATION_SOURCE_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let encoded = registry
                .source(generation_source_handle)?
                .descriptor(role_ordinal)?
                .encode()?;
            u32::try_from(encoded.len()).map_err(|_| TargetReleaseRuntimeError::InvalidInput)
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

/// Copies the Rust-minted canonical stream descriptor for one fixed target
/// role. Role zero is the target identifier and role one is the target order.
///
/// # Safety
///
/// The output pointer must name its declared writable range. A non-null status
/// pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_copy_partial_descriptor(
    generation_source_handle: u32,
    role_ordinal: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let role_ordinal =
            usize::try_from(role_ordinal).map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        TARGET_RELEASE_GENERATION_SOURCE_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let encoded = registry
                .source(generation_source_handle)?
                .descriptor(role_ordinal)?
                .encode()?;
            if output_byte_length != encoded.len() {
                return Err(TargetReleaseRuntimeError::InvalidInput);
            }
            let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
            output.copy_from_slice(&encoded);
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

/// Returns the exact byte length for one canonical target-role stream.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_partial_total_byte_length(
    generation_source_handle: u32,
    role_ordinal: u32,
    status_pointer: *mut u32,
) -> u64 {
    let result = (|| {
        let role_ordinal =
            usize::try_from(role_ordinal).map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        TARGET_RELEASE_GENERATION_SOURCE_REGISTRY.with(|registry| {
            Ok(registry
                .borrow()
                .source(generation_source_handle)?
                .descriptor(role_ordinal)?
                .total_byte_length)
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

/// Copies one exact sequential chunk from the paired target-release streams.
/// Roles cannot be swapped and chunks cannot be skipped or replayed.
///
/// # Safety
///
/// The output pointer must name its declared non-empty writable range. A
/// non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_read_partial_chunk(
    generation_source_handle: u32,
    role_ordinal: u32,
    chunk_index: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() || output_byte_length == 0 {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let role_ordinal =
            usize::try_from(role_ordinal).map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        let chunk_index =
            usize::try_from(chunk_index).map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
        TARGET_RELEASE_GENERATION_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .with_mut(generation_source_handle, |source| {
                    source.read_chunk(role_ordinal, chunk_index, output)
                })
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

/// Retires one generated common proof only after the exact state-certified
/// target-share carrier reproduces its paired stream and proof descriptors.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_target_release_bind_generated_proof(
    generated_common_proof_handle: u32,
    generation_source_handle: u32,
    verified_output_handle: u32,
    target_share_object_handle: u32,
) -> u32 {
    bind_generated_target_release_proof(
        generated_common_proof_handle,
        generation_source_handle,
        verified_output_handle,
        target_share_object_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

/// Permanently discards a cancelled producer-side target-release source.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_target_release_discard_generation_source(
    generation_source_handle: u32,
) -> u32 {
    TARGET_RELEASE_GENERATION_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(generation_source_handle)
            .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
    })
}

/// Opens selected target-share verification from accepted setup, finalized
/// target, reset-safe state output, authenticated paired streams, and one
/// verified target-share board carrier.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. The terminal and
/// non-null status outputs must each name one writable `u32`.
#[allow(clippy::too_many_arguments)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_prepare_verification(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    verified_output_handle: u32,
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability_pointer: *const u8,
    finality_verifier_session_capability_byte_length: usize,
    verified_finality_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    target_share_object_handle: u32,
    target_identifier_pointer: *const u8,
    target_identifier_byte_length: usize,
    target_order_pointer: *const u8,
    target_order_byte_length: usize,
    target_identifier_partial_pointer: *const u8,
    target_identifier_partial_byte_length: usize,
    target_order_partial_pointer: *const u8,
    target_order_partial_byte_length: usize,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if terminal_source_handle_output_pointer.is_null() {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let state_verifier_session_capability = unsafe {
            fixed_input::<STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        }?;
        let finality_verifier_session_capability = unsafe {
            fixed_input::<FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                finality_verifier_session_capability_pointer,
                finality_verifier_session_capability_byte_length,
            )
        }?;
        let board_verifier_session_capability = unsafe {
            fixed_input::<BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        }?;
        let target_identifier_bytes =
            unsafe { variable_input(target_identifier_pointer, target_identifier_byte_length) }?;
        let target_order_bytes =
            unsafe { variable_input(target_order_pointer, target_order_byte_length) }?;
        let target_identifier_partial_bytes = unsafe {
            variable_input(
                target_identifier_partial_pointer,
                target_identifier_partial_byte_length,
            )
        }?;
        let target_order_partial_bytes = unsafe {
            variable_input(
                target_order_partial_pointer,
                target_order_partial_byte_length,
            )
        }?;
        prepare_target_release_verification(
            selected_suite_handle,
            accepted_setup_authority_handle,
            state_verifier_session_handle,
            state_verifier_session_capability,
            verified_reservation_handle,
            verified_output_handle,
            finality_verifier_session_handle,
            finality_verifier_session_capability,
            verified_finality_handle,
            board_verifier_session_handle,
            board_verifier_session_capability,
            target_share_object_handle,
            target_identifier_bytes,
            target_order_bytes,
            target_identifier_partial_bytes,
            target_order_partial_bytes,
        )
    })();
    match result {
        Ok((adapter_handle, terminal_source_handle)) => {
            unsafe {
                terminal_source_handle_output_pointer.write(terminal_source_handle);
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

/// Consumes one positive generic proof and its exact retained authority into a
/// bounded verified paired-share capability.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match finish_target_release_verification(verified_common_proof_handle, terminal_source_handle) {
        Ok(verified_share_handle) => {
            unsafe { write_status(status_pointer, 0) };
            verified_share_handle
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

/// Discards a target-share terminal source after verifier cancellation/reset.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_target_release_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    TARGET_RELEASE_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(terminal_source_handle)
            .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
    })
}

/// Permanently drops a verified paired share that will not be reconstructed.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_target_release_discard_verified_share(
    verified_share_handle: u32,
) -> u32 {
    VERIFIED_TARGET_SHARE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .consume(verified_share_handle)
            .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
    })
}

/// Consumes the exact threshold of distinct verified paired shares and retains
/// one fixed-order reconstructed target pair. The finalized target bytes are
/// re-authenticated from the live finality capability before any share moves.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. Share handles
/// are exactly four little-endian `u32` values. A non-null status pointer must
/// name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_reconstruct_verified_shares(
    finality_verifier_session_handle: u32,
    finality_verifier_session_capability_pointer: *const u8,
    finality_verifier_session_capability_byte_length: usize,
    verified_finality_handle: u32,
    target_identifier_pointer: *const u8,
    target_identifier_byte_length: usize,
    target_order_pointer: *const u8,
    target_order_byte_length: usize,
    verified_share_handles_pointer: *const u8,
    verified_share_handles_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        let finality_verifier_session_capability = unsafe {
            fixed_input::<FINALITY_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                finality_verifier_session_capability_pointer,
                finality_verifier_session_capability_byte_length,
            )
        }?;
        let target_identifier_bytes =
            unsafe { variable_input(target_identifier_pointer, target_identifier_byte_length) }?;
        let target_order_bytes =
            unsafe { variable_input(target_order_pointer, target_order_byte_length) }?;
        let verified_share_handle_bytes = unsafe {
            variable_input(
                verified_share_handles_pointer,
                verified_share_handles_byte_length,
            )
        }?;
        let verified_share_handles =
            decode_verified_target_share_handles(verified_share_handle_bytes)?;
        reconstruct_verified_target_release_shares(
            finality_verifier_session_handle,
            &finality_verifier_session_capability,
            verified_finality_handle,
            target_identifier_bytes,
            target_order_bytes,
            &verified_share_handles,
        )
    })();
    match result {
        Ok(reconstructed_target_pair_handle) => {
            unsafe { write_status(status_pointer, 0) };
            reconstructed_target_pair_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Returns the common logical-slot count for the retained target pair.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_reconstructed_slot_count(
    reconstructed_target_pair_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = RECONSTRUCTED_TARGET_PAIR_REGISTRY.with(|registry| {
        registry
            .borrow()
            .source(reconstructed_target_pair_handle)?
            .slot_count()
    });
    match result {
        Ok(slot_count) => {
            unsafe { write_status(status_pointer, 0) };
            slot_count
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Copies one reconstructed target role in strict target-identifier then
/// target-order sequence as little-endian `u32` logical slots.
///
/// # Safety
///
/// The output pointer must name its declared writable range. A non-null status
/// pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_target_release_copy_reconstructed_role(
    reconstructed_target_pair_handle: u32,
    role_ordinal: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() {
            return Err(TargetReleaseRuntimeError::InvalidInput);
        }
        let role_ordinal =
            usize::try_from(role_ordinal).map_err(|_| TargetReleaseRuntimeError::InvalidInput)?;
        let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
        RECONSTRUCTED_TARGET_PAIR_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .with_mut(reconstructed_target_pair_handle, |source| {
                    source.copy_role(role_ordinal, output)
                })
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

/// Retires a reconstructed target only after both fixed roles were copied.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_target_release_finish_reconstruction(
    reconstructed_target_pair_handle: u32,
) -> u32 {
    RECONSTRUCTED_TARGET_PAIR_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .finish(reconstructed_target_pair_handle)
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
    })
}

/// Permanently discards an incomplete reconstructed target after cancellation.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_target_release_discard_reconstruction(
    reconstructed_target_pair_handle: u32,
) -> u32 {
    RECONSTRUCTED_TARGET_PAIR_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(reconstructed_target_pair_handle)
            .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CommonProofRuntimeError, KLLPS_RECONSTRUCTION_THRESHOLD, PendingReconstructedTargetPair,
        ReconstructedTargetPairRegistry, TargetReleaseRuntimeError,
        decode_verified_target_share_handles,
    };

    #[test]
    fn reconstructed_target_pair_requires_fixed_role_order_and_complete_copy() {
        let pending = PendingReconstructedTargetPair::new(vec![101, 202, 303], vec![7, 8, 9])
            .expect("bounded paired slots are accepted");
        let mut registry = ReconstructedTargetPairRegistry::default();
        let handle = registry.reserve().expect("one destination is available");
        assert_eq!(registry.commit_reserved(handle, pending), handle);
        assert_eq!(
            registry
                .source(handle)
                .expect("retained pair remains live")
                .slot_count()
                .expect("slot count is available before copying"),
            3
        );

        let mut target_order_bytes = [0_u8; 12];
        assert!(matches!(
            registry.with_mut(handle, |source| source
                .copy_role(1, &mut target_order_bytes)),
            Err(TargetReleaseRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase
            ))
        ));
        assert!(matches!(
            registry.finish(handle),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));

        let mut target_identifier_bytes = [0_u8; 12];
        registry
            .with_mut(handle, |source| {
                source.copy_role(0, &mut target_identifier_bytes)
            })
            .expect("target identifier copies first");
        assert_eq!(
            target_identifier_bytes,
            [101, 0, 0, 0, 202, 0, 0, 0, 47, 1, 0, 0]
        );
        assert!(matches!(
            registry.finish(handle),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));
        registry
            .with_mut(handle, |source| {
                source.copy_role(1, &mut target_order_bytes)
            })
            .expect("target order copies second");
        assert_eq!(target_order_bytes, [7, 0, 0, 0, 8, 0, 0, 0, 9, 0, 0, 0]);
        registry
            .finish(handle)
            .expect("complete paired copy retires the result");
        assert!(matches!(
            registry.source(handle),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }

    #[test]
    fn target_share_handle_decoder_requires_one_exact_threshold_array() {
        let expected_handles = [19_u32, 4, 91, 12];
        let encoded_handles = expected_handles
            .iter()
            .flat_map(|handle| handle.to_le_bytes())
            .collect::<Vec<_>>();
        assert_eq!(
            decode_verified_target_share_handles(&encoded_handles)
                .expect("exact little-endian threshold array decodes"),
            expected_handles
        );
        assert_eq!(expected_handles.len(), KLLPS_RECONSTRUCTION_THRESHOLD);
        assert!(matches!(
            decode_verified_target_share_handles(&encoded_handles[..encoded_handles.len() - 1]),
            Err(TargetReleaseRuntimeError::InvalidInput)
        ));
        assert!(matches!(
            decode_verified_target_share_handles(&[]),
            Err(TargetReleaseRuntimeError::InvalidInput)
        ));
    }
}
