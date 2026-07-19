//! Capability-owned construction of the canonical accepted-setup package.
//!
//! The host never supplies a stream descriptor or any of the five object-hash
//! lists. Rust borrows the completed VSS authority, the canonical board's
//! complaint-free response-catalog authority, exact material-source
//! capabilities, and generated or positively verified common-proof
//! capabilities. The resulting bytes remain an untrusted package inventory;
//! accepted setup still requires every exact-family verifier terminal.

use core::slice;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
};

use crate::{
    bgv::proof_suite::{
        AggregateThresholdShareRuntimeError, CommonProofRuntimeError,
        preflight_generated_common_proof_pending_package,
        preflight_verified_common_proof_pending_package, runtime_error_status,
        with_verified_accepted_setup_vss_package_sources,
    },
    foundation::{
        FOUNDATION_PROFILE, Hash512, RefusalReason, StreamDescriptor,
        VerifiedSetupComplaintResolutionReservationHandle,
        reserve_verified_setup_complaint_resolution, restore_verified_setup_complaint_resolution,
        with_reserved_verified_setup_complaint_resolution,
    },
};

use super::{
    canonical_package::{
        CanonicalAcceptedSetupPackage, SelectedAcceptedSetupPublicProofSlot,
        selected_accepted_setup_public_proof_slots,
    },
    verification_assembly::begin_accepted_setup_verification_assembly,
};

const MAXIMUM_RETAINED_PACKAGE_BUILDER_COUNT: usize = 8;
const GENERATED_PROOF_SOURCE_KIND: u32 = 1;
const VERIFIED_PROOF_SOURCE_KIND: u32 = 2;

pub(crate) type CanonicalPackageStreamDescriptorResolver =
    fn(u32) -> Result<StreamDescriptor, CommonProofRuntimeError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalPackageStreamKind {
    CollectivePublicKey,
    EvaluatorKeyStore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PendingProofCapabilityKind {
    Generated,
    Verified,
}

impl PendingProofCapabilityKind {
    fn from_ffi(value: u32) -> Result<Self, CommonProofRuntimeError> {
        match value {
            GENERATED_PROOF_SOURCE_KIND => Ok(Self::Generated),
            VERIFIED_PROOF_SOURCE_KIND => Ok(Self::Verified),
            _ => Err(CommonProofRuntimeError::WrongVerificationBinding),
        }
    }
}

struct BoundStreamDescriptorSource {
    handle: u32,
    resolver: CanonicalPackageStreamDescriptorResolver,
    descriptor: StreamDescriptor,
}

impl BoundStreamDescriptorSource {
    fn revalidated_descriptor(&self) -> Result<StreamDescriptor, CommonProofRuntimeError> {
        let descriptor = (self.resolver)(self.handle)?;
        if descriptor != self.descriptor {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(descriptor)
    }
}

struct PendingProofSource {
    capability_kind: PendingProofCapabilityKind,
    capability_handle: u32,
    canonical_application_statement_bytes: Box<[u8]>,
    descriptor: StreamDescriptor,
}

struct CanonicalAcceptedSetupPackageBuilder {
    vss_recipient_authority_handle: u32,
    complaint_resolution_handle: VerifiedSetupComplaintResolutionReservationHandle,
    expected_suite_identifier: [u8; Hash512::BYTE_LENGTH],
    expected_ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    expected_action_context_hash: [u8; Hash512::BYTE_LENGTH],
    selected_slots: Box<[SelectedAcceptedSetupPublicProofSlot]>,
    collective_public_key_source: Option<BoundStreamDescriptorSource>,
    evaluator_key_store_source: Option<BoundStreamDescriptorSource>,
    ordered_proof_sources: Vec<PendingProofSource>,
    retained_capability_handles: BTreeSet<(PendingProofCapabilityKind, u32)>,
    canonical_package_bytes: Option<Box<[u8]>>,
}

impl CanonicalAcceptedSetupPackageBuilder {
    fn begin(
        vss_recipient_authority_handle: u32,
        board_verifier_session_handle: u32,
        board_verifier_session_capability: &[u8],
    ) -> Result<Self, u32> {
        if vss_recipient_authority_handle == 0 {
            return Err(runtime_error_status(
                CommonProofRuntimeError::WrongVerificationBinding,
            ));
        }
        let selected_slots = selected_accepted_setup_public_proof_slots()
            .map_err(|_| runtime_error_status(CommonProofRuntimeError::WrongVerificationBinding))?
            .into_boxed_slice();
        let complaint_resolution_handle = reserve_verified_setup_complaint_resolution(
            board_verifier_session_handle,
            board_verifier_session_capability,
        )?;
        let expected_context = with_verified_accepted_setup_vss_package_sources(
            vss_recipient_authority_handle,
            |verified_public_randomness, verified_vss_qualification| {
                let context = verified_public_randomness.context();
                with_reserved_verified_setup_complaint_resolution(
                    &complaint_resolution_handle,
                    |resolution| {
                        resolution.require_matches(
                            context.suite_identifier(),
                            context.manifest_hash(),
                            context.ceremony_context_hash(),
                            context.action_context_hash(),
                            context.roster_hash(),
                            verified_vss_qualification
                                .ordered_private_share_acceptance_object_hashes(),
                        )
                    },
                )
                .map_err(|_| {
                    AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState)
                })?
                .map_err(AggregateThresholdShareRuntimeError::Refusal)?;
                Ok((
                    context.suite_identifier().into_bytes(),
                    context.ceremony_context_hash().into_bytes(),
                    context.action_context_hash().into_bytes(),
                ))
            },
        )
        .map_err(|error| match error {
            AggregateThresholdShareRuntimeError::Refusal(reason) => reason.canonical_code() as u32,
            error => runtime_error_status(package_source_runtime_error(error)),
        });
        let (suite_identifier, ceremony_context_hash, action_context_hash) = match expected_context
        {
            Ok(context) => context,
            Err(status) => {
                restore_verified_setup_complaint_resolution(&complaint_resolution_handle)
                    .expect("failed package-builder preflight restores complaint authority");
                return Err(status);
            }
        };
        Ok(Self {
            vss_recipient_authority_handle,
            complaint_resolution_handle,
            expected_suite_identifier: suite_identifier,
            expected_ceremony_context_hash: ceremony_context_hash,
            expected_action_context_hash: action_context_hash,
            selected_slots,
            collective_public_key_source: None,
            evaluator_key_store_source: None,
            ordered_proof_sources: Vec::new(),
            retained_capability_handles: BTreeSet::new(),
            canonical_package_bytes: None,
        })
    }

    fn preflight_stream_source(
        &self,
        kind: CanonicalPackageStreamKind,
        source_handle: u32,
        resolver: CanonicalPackageStreamDescriptorResolver,
    ) -> Result<BoundStreamDescriptorSource, CommonProofRuntimeError> {
        if source_handle == 0 || self.canonical_package_bytes.is_some() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let occupied = match kind {
            CanonicalPackageStreamKind::CollectivePublicKey => {
                self.collective_public_key_source.is_some()
            }
            CanonicalPackageStreamKind::EvaluatorKeyStore => {
                self.evaluator_key_store_source.is_some()
            }
        };
        if occupied {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let descriptor = resolver(source_handle)?;
        Ok(BoundStreamDescriptorSource {
            handle: source_handle,
            resolver,
            descriptor,
        })
    }

    fn commit_stream_source(
        &mut self,
        kind: CanonicalPackageStreamKind,
        source: BoundStreamDescriptorSource,
    ) {
        let destination = match kind {
            CanonicalPackageStreamKind::CollectivePublicKey => {
                &mut self.collective_public_key_source
            }
            CanonicalPackageStreamKind::EvaluatorKeyStore => &mut self.evaluator_key_store_source,
        };
        assert!(destination.replace(source).is_none());
    }

    fn preflight_proof_source(
        &self,
        capability_kind: PendingProofCapabilityKind,
        capability_handle: u32,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<PendingProofSource, CommonProofRuntimeError> {
        if capability_handle == 0
            || canonical_application_statement_bytes.is_empty()
            || canonical_application_statement_bytes.len()
                > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
            || self.canonical_package_bytes.is_some()
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let source_key = (capability_kind, capability_handle);
        if self.retained_capability_handles.contains(&source_key) {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let slot = self
            .selected_slots
            .get(self.ordered_proof_sources.len())
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let descriptor = preflight_proof_source(
            capability_kind,
            capability_handle,
            self.expected_suite_identifier,
            self.expected_ceremony_context_hash,
            self.expected_action_context_hash,
            slot,
            canonical_application_statement_bytes,
        )?;
        Ok(PendingProofSource {
            capability_kind,
            capability_handle,
            canonical_application_statement_bytes: canonical_application_statement_bytes
                .to_vec()
                .into_boxed_slice(),
            descriptor,
        })
    }

    fn commit_proof_source(&mut self, source: PendingProofSource) {
        let source_key = (source.capability_kind, source.capability_handle);
        assert!(self.retained_capability_handles.insert(source_key));
        self.ordered_proof_sources.push(source);
    }

    fn add_proof_source(
        &mut self,
        capability_kind: PendingProofCapabilityKind,
        capability_handle: u32,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let source = self.preflight_proof_source(
            capability_kind,
            capability_handle,
            canonical_application_statement_bytes,
        )?;
        self.commit_proof_source(source);
        Ok(())
    }

    fn contribute_proof_and_stream_source(
        &mut self,
        stream_kind: CanonicalPackageStreamKind,
        stream_source_handle: u32,
        stream_resolver: CanonicalPackageStreamDescriptorResolver,
        capability_kind: PendingProofCapabilityKind,
        capability_handle: u32,
        canonical_application_statement_bytes: &[u8],
    ) -> Result<(), CommonProofRuntimeError> {
        let stream_source =
            self.preflight_stream_source(stream_kind, stream_source_handle, stream_resolver)?;
        let proof_source = self.preflight_proof_source(
            capability_kind,
            capability_handle,
            canonical_application_statement_bytes,
        )?;
        self.commit_stream_source(stream_kind, stream_source);
        self.commit_proof_source(proof_source);
        Ok(())
    }

    fn revalidated_inventory(
        &self,
    ) -> Result<(StreamDescriptor, StreamDescriptor, Vec<StreamDescriptor>), CommonProofRuntimeError>
    {
        if self.ordered_proof_sources.len() != self.selected_slots.len() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let collective_public_key_descriptor = self
            .collective_public_key_source
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .revalidated_descriptor()?;
        let evaluator_key_store_descriptor = self
            .evaluator_key_store_source
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?
            .revalidated_descriptor()?;
        let ordered_proof_descriptors = self
            .ordered_proof_sources
            .iter()
            .zip(&self.selected_slots)
            .map(|(source, slot)| {
                let descriptor = preflight_proof_source(
                    source.capability_kind,
                    source.capability_handle,
                    self.expected_suite_identifier,
                    self.expected_ceremony_context_hash,
                    self.expected_action_context_hash,
                    slot,
                    &source.canonical_application_statement_bytes,
                )?;
                if descriptor != source.descriptor {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding);
                }
                Ok(descriptor)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            collective_public_key_descriptor,
            evaluator_key_store_descriptor,
            ordered_proof_descriptors,
        ))
    }

    fn encode_package(&self) -> Result<Vec<u8>, CommonProofRuntimeError> {
        let (
            collective_public_key_descriptor,
            evaluator_key_store_descriptor,
            ordered_proof_descriptors,
        ) = self.revalidated_inventory()?;
        with_verified_accepted_setup_vss_package_sources(
            self.vss_recipient_authority_handle,
            |verified_public_randomness, verified_vss_qualification| {
                CanonicalAcceptedSetupPackage::encode_authoritative_inventory(
                    verified_public_randomness.ordered_setup_intent_object_hashes(),
                    verified_public_randomness.ordered_commitment_object_hashes(),
                    verified_public_randomness.ordered_reveal_object_hashes(),
                    verified_vss_qualification.ordered_dealer_public_record_object_hashes(),
                    verified_vss_qualification.ordered_private_share_acceptance_object_hashes(),
                    &collective_public_key_descriptor,
                    &evaluator_key_store_descriptor,
                    &ordered_proof_descriptors,
                )
                .map_err(|_| {
                    AggregateThresholdShareRuntimeError::Runtime(
                        CommonProofRuntimeError::WrongVerificationBinding,
                    )
                })
            },
        )
        .map_err(package_source_runtime_error)
    }

    fn finish(&mut self) -> Result<usize, CommonProofRuntimeError> {
        if self.canonical_package_bytes.is_some() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let canonical_package_bytes = self.encode_package()?.into_boxed_slice();
        let byte_length = canonical_package_bytes.len();
        self.canonical_package_bytes = Some(canonical_package_bytes);
        Ok(byte_length)
    }

    fn revalidate_completed(&self) -> Result<&[u8], CommonProofRuntimeError> {
        let retained_bytes = self
            .canonical_package_bytes
            .as_deref()
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let reencoded_bytes = self.encode_package()?;
        if reencoded_bytes != retained_bytes {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(retained_bytes)
    }
}

fn preflight_proof_source(
    capability_kind: PendingProofCapabilityKind,
    capability_handle: u32,
    expected_suite_identifier: [u8; Hash512::BYTE_LENGTH],
    expected_ceremony_context_hash: [u8; Hash512::BYTE_LENGTH],
    expected_action_context_hash: [u8; Hash512::BYTE_LENGTH],
    slot: &SelectedAcceptedSetupPublicProofSlot,
    canonical_application_statement_bytes: &[u8],
) -> Result<StreamDescriptor, CommonProofRuntimeError> {
    match capability_kind {
        PendingProofCapabilityKind::Generated => preflight_generated_common_proof_pending_package(
            capability_handle,
            expected_suite_identifier,
            expected_ceremony_context_hash,
            expected_action_context_hash,
            slot.application_statement_schema_identifier(),
            slot.roster_position(),
            slot.schedule_position(),
            canonical_application_statement_bytes,
        ),
        PendingProofCapabilityKind::Verified => preflight_verified_common_proof_pending_package(
            capability_handle,
            expected_suite_identifier,
            expected_ceremony_context_hash,
            expected_action_context_hash,
            slot.application_statement_schema_identifier(),
            slot.roster_position(),
            slot.schedule_position(),
            canonical_application_statement_bytes,
        ),
    }
}

fn package_source_runtime_error(
    error: AggregateThresholdShareRuntimeError,
) -> CommonProofRuntimeError {
    match error {
        AggregateThresholdShareRuntimeError::Runtime(error) => error,
        _ => CommonProofRuntimeError::WrongVerificationBinding,
    }
}

struct CanonicalAcceptedSetupPackageBuilderRegistry {
    next_handle: u32,
    builders: BTreeMap<u32, CanonicalAcceptedSetupPackageBuilder>,
}

impl Default for CanonicalAcceptedSetupPackageBuilderRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            builders: BTreeMap::new(),
        }
    }
}

impl CanonicalAcceptedSetupPackageBuilderRegistry {
    fn retain(
        &mut self,
        builder: CanonicalAcceptedSetupPackageBuilder,
    ) -> Result<
        u32,
        (
            CommonProofRuntimeError,
            CanonicalAcceptedSetupPackageBuilder,
        ),
    > {
        if self.builders.len() >= MAXIMUM_RETAINED_PACKAGE_BUILDER_COUNT || self.next_handle == 0 {
            return Err((CommonProofRuntimeError::AllocationLimitExceeded, builder));
        }
        let handle = self.next_handle;
        let Some(next_handle) = handle.checked_add(1).filter(|next| *next != 0) else {
            return Err((CommonProofRuntimeError::AllocationLimitExceeded, builder));
        };
        self.next_handle = next_handle;
        if self.builders.insert(handle, builder).is_some() {
            unreachable!("a nonrepeating package-builder handle was already occupied");
        }
        Ok(handle)
    }

    fn get(
        &self,
        handle: u32,
    ) -> Result<&CanonicalAcceptedSetupPackageBuilder, CommonProofRuntimeError> {
        self.builders
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn get_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut CanonicalAcceptedSetupPackageBuilder, CommonProofRuntimeError> {
        self.builders
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<CanonicalAcceptedSetupPackageBuilder, CommonProofRuntimeError> {
        self.builders
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(
        &mut self,
        handle: u32,
        builder: CanonicalAcceptedSetupPackageBuilder,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.builders.insert(handle, builder).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(())
    }
}

thread_local! {
    static CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY:
        RefCell<CanonicalAcceptedSetupPackageBuilderRegistry> =
        RefCell::new(CanonicalAcceptedSetupPackageBuilderRegistry::default());
}

pub(crate) fn contribute_generated_canonical_package_proof_and_stream_source(
    builder_handle: u32,
    stream_kind: CanonicalPackageStreamKind,
    stream_source_handle: u32,
    stream_resolver: CanonicalPackageStreamDescriptorResolver,
    generated_proof_handle: u32,
    canonical_application_statement_bytes: &[u8],
) -> Result<(), CommonProofRuntimeError> {
    CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .get_mut(builder_handle)?
            .contribute_proof_and_stream_source(
                stream_kind,
                stream_source_handle,
                stream_resolver,
                PendingProofCapabilityKind::Generated,
                generated_proof_handle,
                canonical_application_statement_bytes,
            )
    })
}

fn begin_builder(
    vss_recipient_authority_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
) -> Result<u32, u32> {
    let builder = CanonicalAcceptedSetupPackageBuilder::begin(
        vss_recipient_authority_handle,
        board_verifier_session_handle,
        board_verifier_session_capability,
    )?;
    CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY.with(|registry| {
        match registry.borrow_mut().retain(builder) {
            Ok(handle) => Ok(handle),
            Err((error, builder)) => {
                restore_verified_setup_complaint_resolution(&builder.complaint_resolution_handle)
                    .expect("failed package-builder retention restores complaint authority");
                Err(runtime_error_status(error))
            }
        }
    })
}

fn add_proof_source(
    builder_handle: u32,
    capability_kind: PendingProofCapabilityKind,
    capability_handle: u32,
    canonical_application_statement_bytes: &[u8],
) -> Result<(), CommonProofRuntimeError> {
    CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .get_mut(builder_handle)?
            .add_proof_source(
                capability_kind,
                capability_handle,
                canonical_application_statement_bytes,
            )
    })
}

/// Retains one kernel-derived generated proof in the next exact accepted-setup
/// package slot. Family runtimes use this path when the canonical application
/// statement is authority-owned and must not cross the JavaScript boundary.
pub(crate) fn add_generated_proof_source_to_accepted_setup_package_builder(
    builder_handle: u32,
    generated_common_proof_handle: u32,
    canonical_application_statement_bytes: &[u8],
) -> Result<(), CommonProofRuntimeError> {
    add_proof_source(
        builder_handle,
        PendingProofCapabilityKind::Generated,
        generated_common_proof_handle,
        canonical_application_statement_bytes,
    )
}

fn finish_builder(builder_handle: u32) -> Result<usize, CommonProofRuntimeError> {
    CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY
        .with(|registry| registry.borrow_mut().get_mut(builder_handle)?.finish())
}

fn copy_package_bytes(
    builder_handle: u32,
    output: &mut [u8],
) -> Result<(), CommonProofRuntimeError> {
    CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let bytes = registry.get(builder_handle)?.revalidate_completed()?;
        if output.len() != bytes.len() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        output.copy_from_slice(bytes);
        Ok(())
    })
}

fn begin_verification_from_builder(builder_handle: u32) -> Result<u32, CommonProofRuntimeError> {
    let builder = CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY
        .with(|registry| registry.borrow_mut().take(builder_handle))?;
    let result = builder
        .revalidate_completed()
        .and_then(|canonical_package_bytes| {
            begin_accepted_setup_verification_assembly(
                builder.vss_recipient_authority_handle,
                builder.complaint_resolution_handle,
                canonical_package_bytes,
            )
        });
    match result {
        Ok(assembly_handle) => Ok(assembly_handle),
        Err(error) => {
            CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY
                .with(|registry| registry.borrow_mut().restore(builder_handle, builder))?;
            Err(error)
        }
    }
}

fn cancel_builder(builder_handle: u32) -> Result<(), CommonProofRuntimeError> {
    let builder = CANONICAL_ACCEPTED_SETUP_PACKAGE_BUILDER_REGISTRY
        .with(|registry| registry.borrow_mut().take(builder_handle))?;
    restore_verified_setup_complaint_resolution(&builder.complaint_resolution_handle)
        .map_err(|_| CommonProofRuntimeError::UnknownOrStaleHandle)
}

unsafe fn ffi_input<'input>(
    pointer: *const u8,
    byte_length: usize,
) -> Result<&'input [u8], CommonProofRuntimeError> {
    if pointer.is_null()
        || byte_length == 0
        || byte_length > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, byte_length) })
}

unsafe fn ffi_output<'output>(
    pointer: *mut u8,
    byte_length: usize,
) -> Result<&'output mut [u8], CommonProofRuntimeError> {
    if pointer.is_null() || byte_length == 0 {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(unsafe { slice::from_raw_parts_mut(pointer, byte_length) })
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_package_builder_begin(
    vss_recipient_authority_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let board_verifier_session_capability = unsafe {
        ffi_input(
            board_verifier_session_capability_pointer,
            board_verifier_session_capability_byte_length,
        )
    };
    let result = match board_verifier_session_capability {
        Ok(capability) => begin_builder(
            vss_recipient_authority_handle,
            board_verifier_session_handle,
            capability,
        ),
        Err(error) => Err(runtime_error_status(error)),
    };
    match result {
        Ok(builder_handle) => {
            unsafe { write_status(status_pointer, 0) };
            builder_handle
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_package_builder_add_proof_source(
    builder_handle: u32,
    proof_source_kind: u32,
    proof_capability_handle: u32,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
) -> u32 {
    let result = PendingProofCapabilityKind::from_ffi(proof_source_kind).and_then(|kind| {
        unsafe {
            ffi_input(
                canonical_application_statement_pointer,
                canonical_application_statement_byte_length,
            )
        }
        .and_then(|statement| {
            add_proof_source(builder_handle, kind, proof_capability_handle, statement)
        })
    });
    result.map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_package_builder_finish(
    builder_handle: u32,
    status_pointer: *mut u32,
) -> usize {
    match finish_builder(builder_handle) {
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_package_builder_copy_bytes(
    builder_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    unsafe { ffi_output(output_pointer, output_byte_length) }
        .and_then(|output| copy_package_bytes(builder_handle, output))
        .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_verification_begin_from_package_builder(
    builder_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match begin_verification_from_builder(builder_handle) {
        Ok(assembly_handle) => {
            unsafe { write_status(status_pointer, 0) };
            assembly_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_package_builder_cancel(builder_handle: u32) -> u32 {
    cancel_builder(builder_handle).map_or_else(runtime_error_status, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(value: u8) -> StreamDescriptor {
        StreamDescriptor::new(
            1,
            vec![Hash512::from_bytes([value; Hash512::BYTE_LENGTH])],
            Hash512::from_bytes([value.wrapping_add(1); Hash512::BYTE_LENGTH]),
        )
        .expect("test descriptor")
    }

    fn fixed_descriptor_resolver(handle: u32) -> Result<StreamDescriptor, CommonProofRuntimeError> {
        let value =
            u8::try_from(handle).map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        Ok(descriptor(value))
    }

    #[test]
    fn bound_stream_source_revalidates_the_exact_capability_descriptor() {
        let source = BoundStreamDescriptorSource {
            handle: 7,
            resolver: fixed_descriptor_resolver,
            descriptor: descriptor(7),
        };
        assert_eq!(
            source
                .revalidated_descriptor()
                .expect("descriptor revalidates"),
            descriptor(7)
        );
    }

    #[test]
    fn bound_stream_source_rejects_a_changed_retained_descriptor() {
        let source = BoundStreamDescriptorSource {
            handle: 7,
            resolver: fixed_descriptor_resolver,
            descriptor: descriptor(8),
        };
        assert_eq!(
            source.revalidated_descriptor(),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        );
    }
}
