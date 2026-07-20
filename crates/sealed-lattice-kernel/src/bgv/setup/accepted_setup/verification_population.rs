//! Typed browser/WASM population for the accepted-setup proof inventory.
//!
//! Each family prepares the generic common verifier from the exact selected
//! package slot and retained public-randomness authority. Finishing first
//! preflights the typed terminal and its assembly destination while the generic
//! proof capability is still live, then consumes and commits both sources as
//! one infallible transition.

use std::{cell::RefCell, collections::BTreeMap, slice};

use crate::{
    bgv::{
        proof_suite::{
            CommonProofRelationPlanCapability, CommonProofRuntimeError,
            CommonProofSelectedSuiteCapabilityHandle, SelectedApplicationStatementContext,
            VerifiedCommonProofCapabilityHandle, VerifiedCommonProofStatementSource,
            VerifiedKeyRelationColumnEvaluator, VerifiedStatementOwnedTree,
            bind_generated_common_proof_to_verified_statement_source,
            decode_selected_public_key_share_statement, decode_selected_same_secret_statement,
            preflight_and_consume_verified_common_proof_with_family_terminal,
            preflight_generated_common_proof_pending_statement,
            retain_common_proof_verification_family_adapter_from_upstream, runtime_error_status,
            selected_proof_runtime_limits, selected_relation_plan_check_context,
            selected_relation_plans,
        },
        setup::accepted_setup::{
            commit_preflighted_verified_public_key_share_terminal,
            commit_preflighted_verified_same_secret_terminal,
            preflight_verified_public_key_share_terminal_slot,
            preflight_verified_same_secret_terminal_slot,
        },
    },
    foundation::{
        CanonicalDecodeLimits, ProofApplicationBinding, ProofApplicationSlot,
        ProofApplicationSlotCeilings, ProofObjectHeader,
    },
};

use super::{
    verification_assembly::with_accepted_setup_verification_sources,
    verified_terminals::{VerifiedPublicKeyShareTerminal, VerifiedSameSecretTerminal},
};

const MAXIMUM_RETAINED_TERMINAL_SOURCES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptedSetupProofFamily {
    SameSecret,
    PublicKeyShare,
}

impl AcceptedSetupProofFamily {
    const fn schema_identifier(self) -> u16 {
        match self {
            Self::SameSecret => {
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER
            }
            Self::PublicKeyShare => {
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER
            }
        }
    }
}

struct AcceptedSetupVerificationTerminalSource {
    family: AcceptedSetupProofFamily,
    assembly_handle: u32,
    canonical_application_statement_bytes: Box<[u8]>,
}

struct AcceptedSetupVerificationTerminalSourceRegistry {
    next_handle: u32,
    sources: BTreeMap<u32, AcceptedSetupVerificationTerminalSource>,
}

impl Default for AcceptedSetupVerificationTerminalSourceRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            sources: BTreeMap::new(),
        }
    }
}

impl AcceptedSetupVerificationTerminalSourceRegistry {
    fn retain(
        &mut self,
        source: AcceptedSetupVerificationTerminalSource,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.sources.len() >= MAXIMUM_RETAINED_TERMINAL_SOURCES || self.next_handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if self.sources.insert(handle, source).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(handle)
    }

    fn take(
        &mut self,
        handle: u32,
        expected_family: AcceptedSetupProofFamily,
    ) -> Result<AcceptedSetupVerificationTerminalSource, CommonProofRuntimeError> {
        let source = self
            .sources
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if source.family != expected_family {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.sources
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(
        &mut self,
        handle: u32,
        source: AcceptedSetupVerificationTerminalSource,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.sources.insert(handle, source).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(())
    }
}

thread_local! {
    static ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY:
        RefCell<AcceptedSetupVerificationTerminalSourceRegistry> =
            RefCell::new(AcceptedSetupVerificationTerminalSourceRegistry::default());
}

fn prepare_verification(
    family: AcceptedSetupProofFamily,
    selected_suite_handle: u32,
    assembly_handle: u32,
    canonical_application_statement_bytes: &[u8],
) -> Result<(u32, u32), CommonProofRuntimeError> {
    let schema_identifier = family.schema_identifier();
    let canonical_application_statement_bytes = canonical_application_statement_bytes.to_vec();
    let (statement_source, statement_trees, verified_column_evaluator, terminal_source) =
        with_accepted_setup_verification_sources(
            assembly_handle,
            |package, verified_public_randomness| {
                let context = verified_public_randomness.context();
                let statement_context = SelectedApplicationStatementContext::new(
                    context.protocol_version(),
                    context.suite_identifier().into_bytes(),
                    None,
                    None,
                );
                let roster_position = match family {
                    AcceptedSetupProofFamily::SameSecret => decode_selected_same_secret_statement(
                        &canonical_application_statement_bytes,
                        statement_context,
                    )
                    .map(|statement| statement.roster_position()),
                    AcceptedSetupProofFamily::PublicKeyShare => {
                        decode_selected_public_key_share_statement(
                            &canonical_application_statement_bytes,
                            statement_context,
                        )
                        .map(|statement| statement.roster_position())
                    }
                }
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                let selected_slots = package
                    .selected_public_proof_slots()
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                let mut matching_descriptor_indices = selected_slots
                    .iter()
                    .enumerate()
                    .filter(|(_, slot)| {
                        slot.application_statement_schema_identifier() == schema_identifier
                            && slot.roster_position() == Some(roster_position)
                            && slot.schedule_position().is_none()
                    })
                    .map(|(descriptor_index, _)| descriptor_index);
                let proof_descriptor_index = matching_descriptor_indices
                    .next()
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
                if matching_descriptor_indices.next().is_some() {
                    return Err(CommonProofRuntimeError::WrongVerificationBinding);
                }
                let proof_stream_descriptor = package
                    .ordered_proof_descriptors()
                    .get(proof_descriptor_index)
                    .cloned()
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
                let application_slot = ProofApplicationSlot::new(
                    context.suite_identifier(),
                    context.ceremony_context_hash(),
                    context.action_context_hash(),
                    schema_identifier,
                    Some(roster_position),
                    None,
                    None,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                let proof_header = ProofObjectHeader::from_canonical_application_statement(
                    canonical_application_statement_bytes.clone(),
                    &CanonicalDecodeLimits::default(),
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                let proof_header_hash = proof_header
                    .proof_header_hash()
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                let proof_application_binding = ProofApplicationBinding::new(
                    application_slot,
                    proof_header_hash,
                    proof_stream_descriptor,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                let relation_plan_artifact = selected_relation_plans()
                    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?
                    .into_iter()
                    .find(|artifact| {
                        artifact.application_statement_schema_identifier() == schema_identifier
                    })
                    .ok_or(CommonProofRuntimeError::InvalidPlanCapability)?;
                let relation_plan = relation_plan_artifact.compiled_plan();
                let relation_plan_variant = relation_plan
                    .select_variant(None, None)
                    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
                let runtime_limits = selected_proof_runtime_limits(
                    schema_identifier,
                    &canonical_application_statement_bytes,
                    relation_plan_variant,
                )
                .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
                let relation_context = selected_relation_plan_check_context(schema_identifier)
                    .ok_or(CommonProofRuntimeError::InvalidPlanCapability)?;
                let verified_column_evaluator =
                    VerifiedKeyRelationColumnEvaluator::from_verified_public_randomness(
                        verified_public_randomness,
                        &relation_plan_artifact,
                        relation_plan_variant,
                        &relation_context,
                    )
                    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
                let relation_plan_capability =
                    CommonProofRelationPlanCapability::from_compiled_plan(
                        relation_plan,
                        &relation_context,
                        None,
                        None,
                    )
                    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
                let statement_source =
                VerifiedCommonProofStatementSource::from_exact_family_verified_accepted_setup_package(
                    package,
                    verified_public_randomness,
                    proof_descriptor_index,
                    canonical_application_statement_bytes.clone(),
                    proof_application_binding,
                    relation_plan_capability,
                    runtime_limits,
                )?;
                let statement_trees =
                    VerifiedStatementOwnedTree::from_verified_accepted_setup_statement_source(
                        &statement_source,
                        verified_public_randomness,
                    )
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
                Ok((
                    statement_source,
                    statement_trees,
                    verified_column_evaluator,
                    AcceptedSetupVerificationTerminalSource {
                        family,
                        assembly_handle,
                        canonical_application_statement_bytes:
                            canonical_application_statement_bytes
                                .clone()
                                .into_boxed_slice(),
                    },
                ))
            },
        )?;
    let terminal_source_handle = ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().retain(terminal_source))?;
    let selected_suite_handle =
        CommonProofSelectedSuiteCapabilityHandle::from_identifier(selected_suite_handle);
    match retain_common_proof_verification_family_adapter_from_upstream(move |upstream_inputs| {
        upstream_inputs.prepare_statement_tree_family_verification(
            &selected_suite_handle,
            statement_source,
            statement_trees,
            Box::new(verified_column_evaluator),
        )
    }) {
        Ok(adapter_handle) => Ok((adapter_handle, terminal_source_handle)),
        Err(error) => {
            ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .take(terminal_source_handle, family)
                    .map(|_| ())
            })?;
            Err(error)
        }
    }
}

fn finish_same_secret_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source =
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .take(terminal_source_handle, AcceptedSetupProofFamily::SameSecret)
        })?;
    let terminal_source = RefCell::new(Some(terminal_source));
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_proof| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight = with_accepted_setup_verification_sources(
                source.assembly_handle,
                |_, verified_public_randomness| {
                    VerifiedSameSecretTerminal::preflight_from_borrowed_common_proof(
                        verified_proof,
                        &source.canonical_application_statement_bytes,
                        verified_public_randomness,
                    )
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
                },
            )?;
            let prepared_slot = preflight_verified_same_secret_terminal_slot(
                source.assembly_handle,
                terminal_preflight.roster_position(),
            )?;
            Ok((terminal_preflight, prepared_slot))
        },
        |verified_proof, (terminal_preflight, prepared_slot)| {
            let _source = terminal_source
                .borrow_mut()
                .take()
                .expect("terminal preflight retained the exact source");
            let terminal = terminal_preflight.complete(verified_proof);
            commit_preflighted_verified_same_secret_terminal(prepared_slot, terminal);
        },
    );
    if result.is_err()
        && let Some(source) = terminal_source.into_inner()
    {
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .restore(terminal_source_handle, source)
        })?;
    }
    result
}

fn finish_public_key_share_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source =
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry.borrow_mut().take(
                terminal_source_handle,
                AcceptedSetupProofFamily::PublicKeyShare,
            )
        })?;
    let terminal_source = RefCell::new(Some(terminal_source));
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_proof| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight = with_accepted_setup_verification_sources(
                source.assembly_handle,
                |_, verified_public_randomness| {
                    VerifiedPublicKeyShareTerminal::preflight_from_borrowed_common_proof(
                        verified_proof,
                        &source.canonical_application_statement_bytes,
                        verified_public_randomness,
                    )
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
                },
            )?;
            let prepared_slot = preflight_verified_public_key_share_terminal_slot(
                source.assembly_handle,
                terminal_preflight.roster_position(),
            )?;
            Ok((terminal_preflight, prepared_slot))
        },
        |verified_proof, (terminal_preflight, prepared_slot)| {
            let _source = terminal_source
                .borrow_mut()
                .take()
                .expect("terminal preflight retained the exact source");
            let terminal = terminal_preflight.complete(verified_proof);
            commit_preflighted_verified_public_key_share_terminal(prepared_slot, terminal);
        },
    );
    if result.is_err()
        && let Some(source) = terminal_source.into_inner()
    {
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .restore(terminal_source_handle, source)
        })?;
    }
    result
}

fn same_secret_terminal_roster_position(
    source: &AcceptedSetupVerificationTerminalSource,
) -> Result<u16, CommonProofRuntimeError> {
    with_accepted_setup_verification_sources(
        source.assembly_handle,
        |_, verified_public_randomness| {
            let context = verified_public_randomness.context();
            decode_selected_same_secret_statement(
                &source.canonical_application_statement_bytes,
                SelectedApplicationStatementContext::new(
                    context.protocol_version(),
                    context.suite_identifier().into_bytes(),
                    None,
                    None,
                ),
            )
            .map(|statement| statement.roster_position())
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        },
    )
}

fn public_key_share_terminal_roster_position(
    source: &AcceptedSetupVerificationTerminalSource,
) -> Result<u16, CommonProofRuntimeError> {
    with_accepted_setup_verification_sources(
        source.assembly_handle,
        |_, verified_public_randomness| {
            let context = verified_public_randomness.context();
            decode_selected_public_key_share_statement(
                &source.canonical_application_statement_bytes,
                SelectedApplicationStatementContext::new(
                    context.protocol_version(),
                    context.suite_identifier().into_bytes(),
                    None,
                    None,
                ),
            )
            .map(|statement| statement.roster_position())
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        },
    )
}

fn finish_generated_same_secret_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    generated_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source =
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .take(terminal_source_handle, AcceptedSetupProofFamily::SameSecret)
        })?;
    let terminal_source = RefCell::new(Some(terminal_source));
    let generated_proof_descriptor = {
        let preliminary_result = (|| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let roster_position = same_secret_terminal_roster_position(source)?;
            preflight_generated_common_proof_pending_statement(
                generated_common_proof_handle,
                ProofApplicationSlotCeilings::SAME_SECRET_STATEMENT_SCHEMA_IDENTIFIER,
                Some(roster_position),
                None,
                &source.canonical_application_statement_bytes,
            )
        })();
        match preliminary_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let source = terminal_source
                    .into_inner()
                    .expect("the preliminary preflight retained the terminal source");
                ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                    registry
                        .borrow_mut()
                        .restore(terminal_source_handle, source)
                })?;
                return Err(error);
            }
        }
    };
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_proof| {
            if verified_proof.proof_stream_descriptor() != &generated_proof_descriptor {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight = with_accepted_setup_verification_sources(
                source.assembly_handle,
                |_, verified_public_randomness| {
                    VerifiedSameSecretTerminal::preflight_from_borrowed_common_proof(
                        verified_proof,
                        &source.canonical_application_statement_bytes,
                        verified_public_randomness,
                    )
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
                },
            )?;
            let prepared_slot = preflight_verified_same_secret_terminal_slot(
                source.assembly_handle,
                terminal_preflight.roster_position(),
            )?;
            Ok((terminal_preflight, prepared_slot))
        },
        |verified_proof, (terminal_preflight, prepared_slot)| {
            bind_generated_common_proof_to_verified_statement_source(
                generated_common_proof_handle,
                verified_proof
                    .statement_source()
                    .expect("borrowed preflight retained the exact package statement source"),
            )
            .expect("borrowed preflight established the exact generated-proof package binding");
            let _source = terminal_source
                .borrow_mut()
                .take()
                .expect("terminal preflight retained the exact source");
            let terminal = terminal_preflight.complete(verified_proof);
            commit_preflighted_verified_same_secret_terminal(prepared_slot, terminal);
        },
    );
    if result.is_err()
        && let Some(source) = terminal_source.into_inner()
    {
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .restore(terminal_source_handle, source)
        })?;
    }
    result
}

fn finish_generated_public_key_share_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    generated_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source =
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry.borrow_mut().take(
                terminal_source_handle,
                AcceptedSetupProofFamily::PublicKeyShare,
            )
        })?;
    let terminal_source = RefCell::new(Some(terminal_source));
    let generated_proof_descriptor = {
        let preliminary_result = (|| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let roster_position = public_key_share_terminal_roster_position(source)?;
            preflight_generated_common_proof_pending_statement(
                generated_common_proof_handle,
                ProofApplicationSlotCeilings::PUBLIC_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                Some(roster_position),
                None,
                &source.canonical_application_statement_bytes,
            )
        })();
        match preliminary_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let source = terminal_source
                    .into_inner()
                    .expect("the preliminary preflight retained the terminal source");
                ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                    registry
                        .borrow_mut()
                        .restore(terminal_source_handle, source)
                })?;
                return Err(error);
            }
        }
    };
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_proof| {
            if verified_proof.proof_stream_descriptor() != &generated_proof_descriptor {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight = with_accepted_setup_verification_sources(
                source.assembly_handle,
                |_, verified_public_randomness| {
                    VerifiedPublicKeyShareTerminal::preflight_from_borrowed_common_proof(
                        verified_proof,
                        &source.canonical_application_statement_bytes,
                        verified_public_randomness,
                    )
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
                },
            )?;
            let prepared_slot = preflight_verified_public_key_share_terminal_slot(
                source.assembly_handle,
                terminal_preflight.roster_position(),
            )?;
            Ok((terminal_preflight, prepared_slot))
        },
        |verified_proof, (terminal_preflight, prepared_slot)| {
            bind_generated_common_proof_to_verified_statement_source(
                generated_common_proof_handle,
                verified_proof
                    .statement_source()
                    .expect("borrowed preflight retained the exact package statement source"),
            )
            .expect("borrowed preflight established the exact generated-proof package binding");
            let _source = terminal_source
                .borrow_mut()
                .take()
                .expect("terminal preflight retained the exact source");
            let terminal = terminal_preflight.complete(verified_proof);
            commit_preflighted_verified_public_key_share_terminal(prepared_slot, terminal);
        },
    );
    if result.is_err()
        && let Some(source) = terminal_source.into_inner()
    {
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .restore(terminal_source_handle, source)
        })?;
    }
    result
}

fn discard_terminal_source(
    terminal_source_handle: u32,
    family: AcceptedSetupProofFamily,
) -> Result<(), CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(terminal_source_handle, family)
            .map(|_| ())
    })
}

unsafe fn input_bytes<'input>(pointer: *const u8, byte_length: usize) -> &'input [u8] {
    if pointer.is_null() || byte_length == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(pointer, byte_length) }
    }
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

unsafe fn prepare_verification_ffi(
    family: AcceptedSetupProofFamily,
    selected_suite_handle: u32,
    assembly_handle: u32,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if terminal_source_handle_output_pointer.is_null() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let canonical_application_statement_bytes = unsafe {
            input_bytes(
                canonical_application_statement_pointer,
                canonical_application_statement_byte_length,
            )
        };
        if canonical_application_statement_bytes.is_empty() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        prepare_verification(
            family,
            selected_suite_handle,
            assembly_handle,
            canonical_application_statement_bytes,
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

/// Prepares one exact selected same-secret verifier from its package slot.
///
/// # Safety
///
/// The statement pointer must name its declared readable range. The terminal
/// source and non-null status pointers must each name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_same_secret_prepare_verification(
    selected_suite_handle: u32,
    assembly_handle: u32,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_verification_ffi(
            AcceptedSetupProofFamily::SameSecret,
            selected_suite_handle,
            assembly_handle,
            canonical_application_statement_pointer,
            canonical_application_statement_byte_length,
            terminal_source_handle_output_pointer,
            status_pointer,
        )
    }
}

/// Prepares one exact selected public-key-share verifier from its package slot.
///
/// # Safety
///
/// The statement pointer must name its declared readable range. The terminal
/// source and non-null status pointers must each name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_public_key_share_prepare_verification(
    selected_suite_handle: u32,
    assembly_handle: u32,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_verification_ffi(
            AcceptedSetupProofFamily::PublicKeyShare,
            selected_suite_handle,
            assembly_handle,
            canonical_application_statement_pointer,
            canonical_application_statement_byte_length,
            terminal_source_handle_output_pointer,
            status_pointer,
        )
    }
}

/// Consumes one positive same-secret verifier capability into its exact
/// accepted-setup assembly slot.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_same_secret_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> u32 {
    finish_same_secret_verification(verified_common_proof_handle, terminal_source_handle)
        .map_or_else(runtime_error_status, |()| 0)
}

/// Consumes one positive public-key-share verifier capability into its exact
/// accepted-setup assembly slot.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_public_key_share_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> u32 {
    finish_public_key_share_verification(verified_common_proof_handle, terminal_source_handle)
        .map_or_else(runtime_error_status, |()| 0)
}

/// Atomically binds one locally generated same-secret proof to the exact
/// positive package source and commits its verified terminal.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_same_secret_finish_generated_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    generated_common_proof_handle: u32,
) -> u32 {
    finish_generated_same_secret_verification(
        verified_common_proof_handle,
        terminal_source_handle,
        generated_common_proof_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

/// Atomically binds one locally generated public-key-share proof to the exact
/// positive package source and commits its verified terminal.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_public_key_share_finish_generated_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    generated_common_proof_handle: u32,
) -> u32 {
    finish_generated_public_key_share_verification(
        verified_common_proof_handle,
        terminal_source_handle,
        generated_common_proof_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_same_secret_discard_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    discard_terminal_source(terminal_source_handle, AcceptedSetupProofFamily::SameSecret)
        .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_public_key_share_discard_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    discard_terminal_source(
        terminal_source_handle,
        AcceptedSetupProofFamily::PublicKeyShare,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_source_registry_refuses_wrong_family_without_consuming_source() {
        let mut registry = AcceptedSetupVerificationTerminalSourceRegistry::default();
        let handle = registry
            .retain(AcceptedSetupVerificationTerminalSource {
                family: AcceptedSetupProofFamily::SameSecret,
                assembly_handle: 7,
                canonical_application_statement_bytes: vec![1].into_boxed_slice(),
            })
            .expect("source retains");
        assert!(matches!(
            registry.take(handle, AcceptedSetupProofFamily::PublicKeyShare),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
        assert_eq!(
            registry
                .take(handle, AcceptedSetupProofFamily::SameSecret)
                .expect("the exact source remains retryable")
                .assembly_handle,
            7
        );
    }

    #[test]
    fn terminal_source_registry_restore_preserves_one_shot_handle() {
        let mut registry = AcceptedSetupVerificationTerminalSourceRegistry::default();
        let handle = registry
            .retain(AcceptedSetupVerificationTerminalSource {
                family: AcceptedSetupProofFamily::PublicKeyShare,
                assembly_handle: 11,
                canonical_application_statement_bytes: vec![2].into_boxed_slice(),
            })
            .expect("source retains");
        let source = registry
            .take(handle, AcceptedSetupProofFamily::PublicKeyShare)
            .expect("source takes once");
        registry.restore(handle, source).expect("source restores");
        assert!(
            registry
                .take(handle, AcceptedSetupProofFamily::PublicKeyShare)
                .is_ok()
        );
        assert!(matches!(
            registry.take(handle, AcceptedSetupProofFamily::PublicKeyShare),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }
}
