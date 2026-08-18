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
            SourceVerifiedCompactPublicKeyProof, ValidatedRelationPlanArtifact,
            VerifiedCommonProofCapabilityHandle, VerifiedCommonProofStatementSource,
            VerifiedCompactPublicKeyStatementAuthority, VerifiedKeyRelationColumnEvaluator,
            VerifiedStatementOwnedTree, bind_generated_common_proof_to_verified_statement_source,
            compile_public_key_share_relation_plan, compile_same_secret_relation_plan,
            consume_attached_verified_vss_low_degree_evidence,
            consume_reserved_setup_key_relation_generation_statement_source,
            consume_verified_vss_low_degree_evidence, decode_selected_public_key_share_statement,
            decode_selected_same_secret_statement, exact_same_secret_verification_runtime_limits,
            preflight_and_consume_verified_common_proof_with_family_terminal,
            preflight_generated_common_proof_pending_statement,
            require_reserved_setup_key_relation_generation_statement_source,
            reserve_setup_key_relation_generation_statement_source,
            restore_setup_key_relation_generation_statement_source,
            retain_accepted_setup_compact_public_key_verification_source,
            retain_common_proof_verification_family_adapter_from_upstream, runtime_error_status,
            selected_proof_runtime_limits, selected_public_key_share_relation_plan_input,
            selected_relation_plan_check_context, selected_same_secret_relation_plan_input,
        },
        setup::accepted_setup::{
            commit_preflighted_verified_public_key_share_terminal,
            commit_preflighted_verified_same_secret_terminal,
            preflight_verified_public_key_share_terminal_slot,
            preflight_verified_same_secret_terminal_slot,
        },
        setup::{
            SetupKeyRelationProofFamily, VerifiedPublicRandomness,
            VerifiedSetupPolynomialLowDegreePrerequisite,
        },
    },
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, Hash512, ProofApplicationBinding,
        ProofApplicationSlot, ProofApplicationSlotCeilings, ProofObjectHeader,
    },
};

use super::{
    verification_assembly::{
        with_accepted_setup_verification_sources, with_verified_same_secret_terminal,
    },
    verified_terminals::{VerifiedPublicKeyShareTerminal, VerifiedSameSecretTerminal},
};

const MAXIMUM_RETAINED_TERMINAL_SOURCES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AcceptedSetupProofFamily {
    SameSecret,
    PublicKeyShare,
}

enum SameSecretLowDegreeEvidenceSource {
    Available(u32),
    AttachedToGeneration {
        handle: u32,
        generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
    },
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

    const fn setup_key_relation_family(self) -> SetupKeyRelationProofFamily {
        match self {
            Self::SameSecret => SetupKeyRelationProofFamily::SameSecret,
            Self::PublicKeyShare => SetupKeyRelationProofFamily::PublicKeyShare,
        }
    }
}

struct AcceptedSetupVerificationTerminalSource {
    family: AcceptedSetupProofFamily,
    assembly_handle: u32,
    generation_statement_source_handle: Option<u32>,
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

fn take_terminal_source_for_finish(
    terminal_source_handle: u32,
    family: AcceptedSetupProofFamily,
    expects_generated_source: bool,
) -> Result<AcceptedSetupVerificationTerminalSource, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let source = registry.take(terminal_source_handle, family)?;
        if source.generation_statement_source_handle.is_some() != expects_generated_source {
            registry.restore(terminal_source_handle, source)?;
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(source)
    })
}

fn with_prepared_accepted_setup_statement<Output>(
    family: AcceptedSetupProofFamily,
    assembly_handle: u32,
    canonical_application_statement_bytes: Vec<u8>,
    generation_statement_source_handle: Option<u32>,
    finish: impl FnOnce(
        VerifiedCommonProofStatementSource,
        &VerifiedPublicRandomness,
        ValidatedRelationPlanArtifact,
        Option<VerifiedSetupPolynomialLowDegreePrerequisite>,
        AcceptedSetupVerificationTerminalSource,
    ) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
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
            let setup_polynomial_prerequisite = match family {
                AcceptedSetupProofFamily::SameSecret => None,
                AcceptedSetupProofFamily::PublicKeyShare => {
                    Some(with_verified_same_secret_terminal(
                        assembly_handle,
                        roster_position,
                        |terminal| Ok(terminal.setup_polynomial_low_degree_prerequisite()),
                    )?)
                }
            };
            let schema_identifier = family.schema_identifier();
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
            let canonical_proof_byte_length = proof_stream_descriptor.total_byte_length;
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
            let relation_context = selected_relation_plan_check_context(schema_identifier)
                .ok_or(CommonProofRuntimeError::InvalidPlanCapability)?;
            let compiled_relation_plan = match family {
                AcceptedSetupProofFamily::SameSecret => compile_same_secret_relation_plan(
                    &selected_same_secret_relation_plan_input()
                        .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?,
                    &relation_context,
                ),
                AcceptedSetupProofFamily::PublicKeyShare => compile_public_key_share_relation_plan(
                    &selected_public_key_share_relation_plan_input()
                        .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?,
                    &relation_context,
                ),
            }
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
            let relation_plan_artifact = ValidatedRelationPlanArtifact::from_owned_compiled_plan(
                compiled_relation_plan,
                &relation_context,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
            let relation_plan = relation_plan_artifact.compiled_plan();
            let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
                relation_plan,
                &relation_context,
                None,
                None,
            )
            .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
            let runtime_limits = match family {
                AcceptedSetupProofFamily::SameSecret => {
                    exact_same_secret_verification_runtime_limits(
                        &relation_plan_capability,
                        canonical_proof_byte_length,
                    )?
                }
                AcceptedSetupProofFamily::PublicKeyShare => selected_proof_runtime_limits(
                    &canonical_application_statement_bytes,
                    &relation_plan_capability,
                )
                .map_err(|_| CommonProofRuntimeError::InvalidLimits)?,
            };
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
            finish(
                statement_source,
                verified_public_randomness,
                relation_plan_artifact,
                setup_polynomial_prerequisite,
                AcceptedSetupVerificationTerminalSource {
                    family,
                    assembly_handle,
                    generation_statement_source_handle,
                    canonical_application_statement_bytes: canonical_application_statement_bytes
                        .into_boxed_slice(),
                },
            )
        },
    )
}

fn prepare_verification(
    family: AcceptedSetupProofFamily,
    selected_suite_handle: u32,
    assembly_handle: u32,
    same_secret_low_degree_evidence_source: Option<SameSecretLowDegreeEvidenceSource>,
    canonical_application_statement_bytes: &[u8],
    generation_statement_source_handle: Option<u32>,
) -> Result<(u32, u32), CommonProofRuntimeError> {
    if canonical_application_statement_bytes.is_empty()
        || canonical_application_statement_bytes.len()
            > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let same_secret_prerequisite = match (family, same_secret_low_degree_evidence_source) {
        (
            AcceptedSetupProofFamily::SameSecret,
            Some(SameSecretLowDegreeEvidenceSource::Available(handle)),
        ) => Some(consume_verified_vss_low_degree_evidence(handle)?),
        (
            AcceptedSetupProofFamily::SameSecret,
            Some(SameSecretLowDegreeEvidenceSource::AttachedToGeneration {
                handle,
                generation_binding_hash,
            }),
        ) => Some(consume_attached_verified_vss_low_degree_evidence(
            handle,
            generation_binding_hash,
        )?),
        (AcceptedSetupProofFamily::PublicKeyShare, None) => None,
        _ => return Err(CommonProofRuntimeError::WrongVerificationBinding),
    };
    let canonical_application_statement_bytes = canonical_application_statement_bytes.to_vec();
    let (
        statement_source,
        statement_trees,
        verified_column_evaluator,
        setup_polynomial_prerequisite,
        terminal_source,
    ) = with_prepared_accepted_setup_statement(
        family,
        assembly_handle,
        canonical_application_statement_bytes,
        generation_statement_source_handle,
        |statement_source,
         verified_public_randomness,
         relation_plan_artifact,
         setup_polynomial_prerequisite,
         terminal_source| {
            let relation_plan = relation_plan_artifact.compiled_plan();
            let relation_plan_variant = relation_plan
                .select_variant(None, None)
                .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
            let verified_column_evaluator =
                VerifiedKeyRelationColumnEvaluator::from_verified_public_randomness(
                    verified_public_randomness,
                    &relation_plan_artifact,
                    relation_plan_variant,
                )
                .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
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
                setup_polynomial_prerequisite,
                terminal_source,
            ))
        },
    )?;
    let terminal_source_handle = ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().retain(terminal_source))?;
    let selected_suite_handle =
        CommonProofSelectedSuiteCapabilityHandle::from_identifier(selected_suite_handle);
    match retain_common_proof_verification_family_adapter_from_upstream(move |upstream_inputs| {
        match (
            family,
            same_secret_prerequisite,
            setup_polynomial_prerequisite,
        ) {
            (AcceptedSetupProofFamily::SameSecret, Some(prerequisite), None) => upstream_inputs
                .prepare_same_secret_row_code_whir_verification(
                    &selected_suite_handle,
                    statement_source,
                    statement_trees,
                    Box::new(verified_column_evaluator),
                    prerequisite,
                ),
            (AcceptedSetupProofFamily::PublicKeyShare, None, Some(prerequisite)) => upstream_inputs
                .prepare_setup_polynomial_bound_row_code_whir_verification(
                    &selected_suite_handle,
                    statement_source,
                    statement_trees,
                    Box::new(verified_column_evaluator),
                    prerequisite,
                ),
            _ => Err(CommonProofRuntimeError::WrongVerificationBinding),
        }
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

pub(in crate::bgv) fn reserve_compact_public_key_verification_source(
    assembly_handle: u32,
    canonical_application_statement_bytes: &[u8],
) -> Result<(VerifiedCompactPublicKeyStatementAuthority, u32), CommonProofRuntimeError> {
    if canonical_application_statement_bytes.is_empty()
        || canonical_application_statement_bytes.len()
            > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let (statement_authority, terminal_source) = with_prepared_accepted_setup_statement(
        AcceptedSetupProofFamily::PublicKeyShare,
        assembly_handle,
        canonical_application_statement_bytes.to_vec(),
        None,
        |statement_source,
         verified_public_randomness,
         relation_plan_artifact,
         setup_polynomial_prerequisite,
         terminal_source| {
            drop(relation_plan_artifact);
            let prerequisite = setup_polynomial_prerequisite
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let statement_authority =
                VerifiedCompactPublicKeyStatementAuthority::from_verified_accepted_setup_sources(
                    statement_source,
                    verified_public_randomness,
                    prerequisite,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            Ok((statement_authority, terminal_source))
        },
    )?;
    let terminal_source_handle = ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().retain(terminal_source))?;
    Ok((statement_authority, terminal_source_handle))
}

pub(in crate::bgv) fn commit_source_verified_compact_public_key_proof(
    terminal_source_handle: u32,
    verified_proof: SourceVerifiedCompactPublicKeyProof,
) -> Result<
    (),
    (
        CommonProofRuntimeError,
        Box<SourceVerifiedCompactPublicKeyProof>,
    ),
> {
    let terminal_source = match take_terminal_source_for_finish(
        terminal_source_handle,
        AcceptedSetupProofFamily::PublicKeyShare,
        false,
    ) {
        Ok(source) => source,
        Err(error) => return Err((error, Box::new(verified_proof))),
    };
    let prepared_slot = match preflight_verified_public_key_share_terminal_slot(
        terminal_source.assembly_handle,
        verified_proof.roster_position(),
    ) {
        Ok(prepared_slot) => prepared_slot,
        Err(error) => {
            let restoration =
                ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                    registry
                        .borrow_mut()
                        .restore(terminal_source_handle, terminal_source)
                });
            return Err((restoration.err().unwrap_or(error), Box::new(verified_proof)));
        }
    };
    let terminal = VerifiedPublicKeyShareTerminal::from_source_verified_compact_public_key_proof(
        verified_proof,
    );
    commit_preflighted_verified_public_key_share_terminal(prepared_slot, terminal);
    Ok(())
}

pub(in crate::bgv) fn discard_compact_public_key_verification_source(
    terminal_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    discard_terminal_source(
        terminal_source_handle,
        AcceptedSetupProofFamily::PublicKeyShare,
    )
}

fn prepare_generated_verification(
    family: AcceptedSetupProofFamily,
    selected_suite_handle: u32,
    assembly_handle: u32,
    generation_statement_source_handle: u32,
) -> Result<(u32, u32), CommonProofRuntimeError> {
    let setup_key_relation_family = family.setup_key_relation_family();
    let statement_source = reserve_setup_key_relation_generation_statement_source(
        generation_statement_source_handle,
        setup_key_relation_family,
    )?;
    let same_secret_low_degree_evidence_source = match family {
        AcceptedSetupProofFamily::SameSecret => {
            let (handle, generation_binding_hash) =
                statement_source.same_secret_low_degree_evidence_binding()?;
            Some(SameSecretLowDegreeEvidenceSource::AttachedToGeneration {
                handle,
                generation_binding_hash,
            })
        }
        AcceptedSetupProofFamily::PublicKeyShare => None,
    };
    let result = prepare_verification(
        family,
        selected_suite_handle,
        assembly_handle,
        same_secret_low_degree_evidence_source,
        statement_source.canonical_application_statement_bytes(),
        Some(generation_statement_source_handle),
    );
    if result.is_err() {
        restore_setup_key_relation_generation_statement_source(
            generation_statement_source_handle,
            setup_key_relation_family,
        )?;
    }
    result
}

fn finish_same_secret_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source = take_terminal_source_for_finish(
        terminal_source_handle,
        AcceptedSetupProofFamily::SameSecret,
        false,
    )?;
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
    let terminal_source = take_terminal_source_for_finish(
        terminal_source_handle,
        AcceptedSetupProofFamily::PublicKeyShare,
        false,
    )?;
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
    let terminal_source = take_terminal_source_for_finish(
        terminal_source_handle,
        AcceptedSetupProofFamily::SameSecret,
        true,
    )?;
    let terminal_source = RefCell::new(Some(terminal_source));
    let generated_proof_descriptor = {
        let preliminary_result = (|| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let generation_statement_source_handle = source
                .generation_statement_source_handle
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let generation_statement_source =
                require_reserved_setup_key_relation_generation_statement_source(
                    generation_statement_source_handle,
                    SetupKeyRelationProofFamily::SameSecret,
                    generated_common_proof_handle,
                )?;
            if generation_statement_source.canonical_application_statement_bytes()
                != source.canonical_application_statement_bytes.as_ref()
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
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
            let generation_statement_source_handle = terminal_source
                .borrow()
                .as_ref()
                .and_then(|source| source.generation_statement_source_handle)
                .expect("generated terminal preflight retained its statement source");
            bind_generated_common_proof_to_verified_statement_source(
                generated_common_proof_handle,
                verified_proof
                    .statement_source()
                    .expect("borrowed preflight retained the exact package statement source"),
            )
            .expect("borrowed preflight established the exact generated-proof package binding");
            consume_reserved_setup_key_relation_generation_statement_source(
                generation_statement_source_handle,
                SetupKeyRelationProofFamily::SameSecret,
            )
            .expect("generated proof binding retained its reserved statement source");
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
    let terminal_source = take_terminal_source_for_finish(
        terminal_source_handle,
        AcceptedSetupProofFamily::PublicKeyShare,
        true,
    )?;
    let terminal_source = RefCell::new(Some(terminal_source));
    let generated_proof_descriptor = {
        let preliminary_result = (|| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let generation_statement_source_handle = source
                .generation_statement_source_handle
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let generation_statement_source =
                require_reserved_setup_key_relation_generation_statement_source(
                    generation_statement_source_handle,
                    SetupKeyRelationProofFamily::PublicKeyShare,
                    generated_common_proof_handle,
                )?;
            if generation_statement_source.canonical_application_statement_bytes()
                != source.canonical_application_statement_bytes.as_ref()
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
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
            let generation_statement_source_handle = terminal_source
                .borrow()
                .as_ref()
                .and_then(|source| source.generation_statement_source_handle)
                .expect("generated terminal preflight retained its statement source");
            bind_generated_common_proof_to_verified_statement_source(
                generated_common_proof_handle,
                verified_proof
                    .statement_source()
                    .expect("borrowed preflight retained the exact package statement source"),
            )
            .expect("borrowed preflight established the exact generated-proof package binding");
            consume_reserved_setup_key_relation_generation_statement_source(
                generation_statement_source_handle,
                SetupKeyRelationProofFamily::PublicKeyShare,
            )
            .expect("generated proof binding retained its reserved statement source");
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
    let source = ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(terminal_source_handle, family))?;
    if let Some(generation_statement_source_handle) = source.generation_statement_source_handle
        && let Err(error) = restore_setup_key_relation_generation_statement_source(
            generation_statement_source_handle,
            family.setup_key_relation_family(),
        )
    {
        ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .restore(terminal_source_handle, source)
        })?;
        return Err(error);
    }
    Ok(())
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

struct PrepareVerificationFfiInput {
    selected_suite_handle: u32,
    assembly_handle: u32,
    vss_low_degree_evidence_handle: Option<u32>,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
}

unsafe fn prepare_verification_ffi(
    family: AcceptedSetupProofFamily,
    input: PrepareVerificationFfiInput,
) -> u32 {
    let result = (|| {
        if input.terminal_source_handle_output_pointer.is_null() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        if input.canonical_application_statement_byte_length == 0
            || input.canonical_application_statement_byte_length
                > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let canonical_application_statement_bytes = unsafe {
            input_bytes(
                input.canonical_application_statement_pointer,
                input.canonical_application_statement_byte_length,
            )
        };
        prepare_verification(
            family,
            input.selected_suite_handle,
            input.assembly_handle,
            input
                .vss_low_degree_evidence_handle
                .map(SameSecretLowDegreeEvidenceSource::Available),
            canonical_application_statement_bytes,
            None,
        )
    })();
    match result {
        Ok((adapter_handle, terminal_source_handle)) => {
            unsafe {
                input
                    .terminal_source_handle_output_pointer
                    .write(terminal_source_handle);
                write_status(input.status_pointer, 0);
            }
            adapter_handle
        }
        Err(error) => {
            unsafe { write_status(input.status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

unsafe fn prepare_generated_verification_ffi(
    family: AcceptedSetupProofFamily,
    selected_suite_handle: u32,
    assembly_handle: u32,
    generation_statement_source_handle: u32,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = if terminal_source_handle_output_pointer.is_null() {
        Err(CommonProofRuntimeError::WrongVerificationBinding)
    } else {
        prepare_generated_verification(
            family,
            selected_suite_handle,
            assembly_handle,
            generation_statement_source_handle,
        )
    };
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
    vss_low_degree_evidence_handle: u32,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_verification_ffi(
            AcceptedSetupProofFamily::SameSecret,
            PrepareVerificationFfiInput {
                selected_suite_handle,
                assembly_handle,
                vss_low_degree_evidence_handle: Some(vss_low_degree_evidence_handle),
                canonical_application_statement_pointer,
                canonical_application_statement_byte_length,
                terminal_source_handle_output_pointer,
                status_pointer,
            },
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
            PrepareVerificationFfiInput {
                selected_suite_handle,
                assembly_handle,
                vss_low_degree_evidence_handle: None,
                canonical_application_statement_pointer,
                canonical_application_statement_byte_length,
                terminal_source_handle_output_pointer,
                status_pointer,
            },
        )
    }
}

/// Retains the exact accepted package statement and same-secret prerequisite
/// for the source-bound compact public-key verifier. The returned handle owns
/// all four public-input bindings; callers provide only proof bytes and public
/// input bytes to the subsequent begin or resume boundary.
///
/// # Safety
///
/// The statement pointer must name its declared readable range. A non-null
/// status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_public_key_share_prepare_compact_verification(
    assembly_handle: u32,
    canonical_application_statement_pointer: *const u8,
    canonical_application_statement_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let canonical_application_statement_bytes = unsafe {
        input_bytes(
            canonical_application_statement_pointer,
            canonical_application_statement_byte_length,
        )
    };
    let result = (|| {
        let (statement_authority, terminal_source_handle) =
            reserve_compact_public_key_verification_source(
                assembly_handle,
                canonical_application_statement_bytes,
            )?;
        match retain_accepted_setup_compact_public_key_verification_source(
            statement_authority,
            terminal_source_handle,
        ) {
            Ok(handle) => Ok(handle),
            Err(error) => {
                discard_compact_public_key_verification_source(terminal_source_handle)?;
                Err(error)
            }
        }
    })();
    match result {
        Ok(handle) => {
            unsafe { write_status(status_pointer, 0) };
            handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Prepares one exact selected same-secret verifier directly from a reserved
/// Rust-owned generation statement source.
///
/// # Safety
///
/// The terminal source and non-null status pointers must each name one
/// writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_same_secret_prepare_generated_verification(
    selected_suite_handle: u32,
    assembly_handle: u32,
    generation_statement_source_handle: u32,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generated_verification_ffi(
            AcceptedSetupProofFamily::SameSecret,
            selected_suite_handle,
            assembly_handle,
            generation_statement_source_handle,
            terminal_source_handle_output_pointer,
            status_pointer,
        )
    }
}

/// Prepares one exact selected public-key-share verifier directly from a
/// reserved Rust-owned generation statement source.
///
/// # Safety
///
/// The terminal source and non-null status pointers must each name one
/// writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_public_key_share_prepare_generated_verification(
    selected_suite_handle: u32,
    assembly_handle: u32,
    generation_statement_source_handle: u32,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generated_verification_ffi(
            AcceptedSetupProofFamily::PublicKeyShare,
            selected_suite_handle,
            assembly_handle,
            generation_statement_source_handle,
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
    fn verification_ffi_refuses_oversized_statement_before_reading_its_pointer() {
        let mut terminal_source_handle = u32::MAX;
        let mut status = u32::MAX;
        let adapter_handle = unsafe {
            prepare_verification_ffi(
                AcceptedSetupProofFamily::SameSecret,
                PrepareVerificationFfiInput {
                    selected_suite_handle: 1,
                    assembly_handle: 1,
                    vss_low_degree_evidence_handle: Some(1),
                    canonical_application_statement_pointer: core::ptr::NonNull::<u8>::dangling()
                        .as_ptr(),
                    canonical_application_statement_byte_length: FOUNDATION_PROFILE
                        .maximum_copied_buffer_byte_length
                        + 1,
                    terminal_source_handle_output_pointer: &mut terminal_source_handle,
                    status_pointer: &mut status,
                },
            )
        };

        assert_eq!(adapter_handle, 0);
        assert_eq!(terminal_source_handle, u32::MAX);
        assert_eq!(
            status,
            runtime_error_status(CommonProofRuntimeError::WrongVerificationBinding)
        );
    }

    #[test]
    fn terminal_source_registry_refuses_wrong_family_without_consuming_source() {
        let mut registry = AcceptedSetupVerificationTerminalSourceRegistry::default();
        let handle = registry
            .retain(AcceptedSetupVerificationTerminalSource {
                family: AcceptedSetupProofFamily::SameSecret,
                assembly_handle: 7,
                generation_statement_source_handle: None,
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
                generation_statement_source_handle: None,
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

    #[test]
    fn terminal_source_origin_cannot_cross_normal_and_generated_finish_paths() {
        let terminal_source_handle = ACCEPTED_SETUP_VERIFICATION_TERMINAL_SOURCE_REGISTRY
            .with(|registry| {
                registry
                    .borrow_mut()
                    .retain(AcceptedSetupVerificationTerminalSource {
                        family: AcceptedSetupProofFamily::SameSecret,
                        assembly_handle: 17,
                        generation_statement_source_handle: Some(23),
                        canonical_application_statement_bytes: vec![3].into_boxed_slice(),
                    })
            })
            .expect("generated terminal source retains");
        assert!(matches!(
            take_terminal_source_for_finish(
                terminal_source_handle,
                AcceptedSetupProofFamily::SameSecret,
                false,
            ),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
        let source = take_terminal_source_for_finish(
            terminal_source_handle,
            AcceptedSetupProofFamily::SameSecret,
            true,
        )
        .expect("the generated finish path consumes the restored terminal source");
        assert_eq!(source.generation_statement_source_handle, Some(23));
        assert!(matches!(
            take_terminal_source_for_finish(
                terminal_source_handle,
                AcceptedSetupProofFamily::SameSecret,
                true,
            ),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }
}
