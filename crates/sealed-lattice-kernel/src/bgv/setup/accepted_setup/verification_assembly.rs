use std::{cell::RefCell, collections::BTreeMap, slice};

use crate::{
    bgv::proof_suite::{
        AggregateThresholdShareRuntimeError, CommonProofRuntimeError, VerifiedEvaluatorKeyStore,
        VerifiedRelinearizationAggregateMaterial, aggregate_threshold_share_runtime_error_status,
        consume_verified_accepted_setup_vss_qualification,
        restore_verified_accepted_setup_vss_qualification, runtime_error_status,
        with_verified_accepted_setup_vss_public_randomness,
    },
    foundation::{
        CanonicalDecodeLimits, FOUNDATION_PROFILE, RefusalReason,
        VerifiedSetupComplaintResolutionReservationHandle,
        restore_verified_setup_complaint_resolution,
        with_reserved_verified_setup_complaint_resolution,
    },
};

use super::{
    authority::{VerifiedAcceptedSetupAuthorityHandle, release_verified_accepted_setup_authority},
    canonical_package::CanonicalAcceptedSetupPackage,
    evaluator_source::VerifiedAcceptedSetupEvaluatorSourceCatalog,
    finalization::{VerifiedAcceptedSetupFinalizationInput, finalize_verified_accepted_setup},
    prepackage_evaluator_source_catalog::{
        consume_completed_prepackage_evaluator_source_catalog,
        with_completed_prepackage_evaluator_source_catalog,
    },
    verified_public_proof_catalog::VerifiedAcceptedSetupPublicProofCatalog,
    verified_public_randomness::VerifiedPublicRandomness,
    verified_terminals::{
        VerifiedCollectivePublicKeyTerminal, VerifiedCollectivePublicKeyTerminalPreflight,
        VerifiedPublicKeyShareTerminal, VerifiedSameSecretTerminal,
    },
};

/// Process-local collection authority for the exact accepted-setup public
/// proof inventory. Family verifiers insert only their opaque typed terminals;
/// transported roots, positions, descriptors, or completion claims cannot
/// populate a slot.
struct AcceptedSetupVerificationAssembly {
    vss_recipient_authority_handle: u32,
    complaint_resolution_handle: VerifiedSetupComplaintResolutionReservationHandle,
    package: Option<CanonicalAcceptedSetupPackage>,
    expected_protocol_version: u16,
    expected_suite_identifier: [u8; 64],
    expected_ceremony_context_hash: [u8; 64],
    expected_action_context_hash: [u8; 64],
    expected_ordered_participant_identities: Box<[[u8; 64]]>,
    expected_manifest_hash: [u8; 64],
    expected_roster_hash: [u8; 64],
    expected_setup_proof_context_hash: [u8; 64],
    same_secret_terminals: BTreeMap<u16, VerifiedSameSecretTerminal>,
    public_key_share_terminals: BTreeMap<u16, VerifiedPublicKeyShareTerminal>,
    collective_public_key_terminal: Option<VerifiedCollectivePublicKeyTerminal>,
    relinearization_aggregate: Option<VerifiedRelinearizationAggregateMaterial>,
    evaluator_source_catalog: Option<VerifiedAcceptedSetupEvaluatorSourceCatalog>,
    evaluator_sources_completed: bool,
    verified_evaluator_key_store: Option<VerifiedEvaluatorKeyStore>,
    public_proof_catalog: Option<VerifiedAcceptedSetupPublicProofCatalog>,
}

impl AcceptedSetupVerificationAssembly {
    fn new(
        vss_recipient_authority_handle: u32,
        complaint_resolution_handle: VerifiedSetupComplaintResolutionReservationHandle,
        package: CanonicalAcceptedSetupPackage,
        verified_public_randomness: &VerifiedPublicRandomness,
    ) -> Result<Self, CommonProofRuntimeError> {
        let context = verified_public_randomness.context();
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if vss_recipient_authority_handle == 0
            || verified_public_randomness
                .ordered_participant_identities()
                .len()
                != participant_count
            || package.setup_intent_object_hashes()
                != verified_public_randomness.ordered_setup_intent_object_hashes()
            || package.public_randomness_commitment_object_hashes()
                != verified_public_randomness.ordered_commitment_object_hashes()
            || package.public_randomness_reveal_object_hashes()
                != verified_public_randomness.ordered_reveal_object_hashes()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        with_reserved_verified_setup_complaint_resolution(
            &complaint_resolution_handle,
            |resolution| {
                resolution.require_matches(
                    context.suite_identifier(),
                    context.manifest_hash(),
                    context.ceremony_context_hash(),
                    context.action_context_hash(),
                    context.roster_hash(),
                    package.private_share_acceptance_object_hashes(),
                )
            },
        )
        .map_err(|_| CommonProofRuntimeError::UnknownOrStaleHandle)?
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let selected_slots = package
            .selected_public_proof_slots()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if selected_slots.len() != package.ordered_proof_descriptors().len() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }

        Ok(Self {
            vss_recipient_authority_handle,
            complaint_resolution_handle,
            package: Some(package),
            expected_protocol_version: context.protocol_version(),
            expected_suite_identifier: context.suite_identifier().into_bytes(),
            expected_ceremony_context_hash: context.ceremony_context_hash().into_bytes(),
            expected_action_context_hash: context.action_context_hash().into_bytes(),
            expected_ordered_participant_identities: verified_public_randomness
                .ordered_participant_identities()
                .iter()
                .map(|identity| identity.into_bytes())
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            expected_manifest_hash: context.manifest_hash().into_bytes(),
            expected_roster_hash: context.roster_hash().into_bytes(),
            expected_setup_proof_context_hash: verified_public_randomness
                .setup_proof_context_hash()
                .into_bytes(),
            same_secret_terminals: BTreeMap::new(),
            public_key_share_terminals: BTreeMap::new(),
            collective_public_key_terminal: None,
            relinearization_aggregate: None,
            evaluator_source_catalog: None,
            evaluator_sources_completed: false,
            verified_evaluator_key_store: None,
            public_proof_catalog: None,
        })
    }

    fn require_collecting(&self) -> Result<(), CommonProofRuntimeError> {
        if self.public_proof_catalog.is_some() {
            Err(CommonProofRuntimeError::WrongOperationPhase)
        } else {
            Ok(())
        }
    }

    fn evaluator_catalog_matches_expected_context(
        &self,
        catalog: &VerifiedAcceptedSetupEvaluatorSourceCatalog,
    ) -> bool {
        catalog.protocol_version() == self.expected_protocol_version
            && catalog.suite_identifier() == self.expected_suite_identifier
            && catalog.ceremony_context_hash() == self.expected_ceremony_context_hash
            && catalog.action_context_hash() == self.expected_action_context_hash
            && catalog.manifest_hash() == self.expected_manifest_hash
            && catalog.roster_hash() == self.expected_roster_hash
            && catalog.setup_proof_context_hash() == self.expected_setup_proof_context_hash
            && catalog.matches_ordered_participant_identities(
                &self.expected_ordered_participant_identities,
            )
    }

    fn complete_evaluator_source_catalog(&mut self) -> Result<(), CommonProofRuntimeError> {
        self.require_collecting()?;
        if self.evaluator_sources_completed {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        if self.evaluator_source_catalog.is_none() || self.relinearization_aggregate.is_none() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.evaluator_sources_completed = true;
        Ok(())
    }

    fn complete_public_proof_catalog(&mut self) -> Result<(), CommonProofRuntimeError> {
        self.require_collecting()?;
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if self.same_secret_terminals.len() != participant_count
            || self.public_key_share_terminals.len() != participant_count
            || self.collective_public_key_terminal.is_none()
            || self.relinearization_aggregate.is_none()
            || !self.evaluator_sources_completed
            || self.evaluator_source_catalog.is_none()
            || self.verified_evaluator_key_store.is_none()
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }

        let mut ordered_same_secret_terminals = Vec::new();
        ordered_same_secret_terminals
            .try_reserve_exact(participant_count)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        let mut ordered_public_key_share_terminals = Vec::new();
        ordered_public_key_share_terminals
            .try_reserve_exact(participant_count)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            ordered_same_secret_terminals.push(
                self.same_secret_terminals
                    .get(&roster_position)
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?,
            );
            ordered_public_key_share_terminals.push(
                self.public_key_share_terminals
                    .get(&roster_position)
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?,
            );
        }
        let preflight =
            VerifiedAcceptedSetupPublicProofCatalog::preflight_from_verified_family_terminals(
                &ordered_same_secret_terminals,
                &ordered_public_key_share_terminals,
                self.collective_public_key_terminal
                    .as_ref()
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?,
                self.relinearization_aggregate
                    .as_ref()
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?,
                self.evaluator_source_catalog
                    .as_ref()
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?,
                self.verified_evaluator_key_store
                    .as_ref()
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if self
            .package
            .as_ref()
            .expect("a retained verification assembly owns its package")
            .ordered_proof_descriptors()
            != preflight.ordered_proof_stream_descriptors()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        drop(ordered_same_secret_terminals);
        drop(ordered_public_key_share_terminals);

        self.same_secret_terminals.clear();
        self.public_key_share_terminals.clear();
        let collective_public_key_terminal = self
            .collective_public_key_terminal
            .take()
            .expect("borrowed preflight established the collective public-key terminal");
        let _relinearization_aggregate = self
            .relinearization_aggregate
            .take()
            .expect("borrowed preflight established the relinearization aggregate");
        let _evaluator_source_catalog = self
            .evaluator_source_catalog
            .take()
            .expect("borrowed preflight established the evaluator source catalog");
        let verified_evaluator_key_store = self
            .verified_evaluator_key_store
            .take()
            .expect("borrowed preflight established the evaluator-key store");
        let catalog = VerifiedAcceptedSetupPublicProofCatalog::from_preflighted_family_terminals(
            preflight,
            collective_public_key_terminal,
            verified_evaluator_key_store,
        );
        self.public_proof_catalog = Some(catalog);
        Ok(())
    }
}

struct AcceptedSetupVerificationAssemblyRegistry {
    next_handle: u32,
    assemblies: BTreeMap<u32, AcceptedSetupVerificationAssembly>,
}

impl Default for AcceptedSetupVerificationAssemblyRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            assemblies: BTreeMap::new(),
        }
    }
}

impl AcceptedSetupVerificationAssemblyRegistry {
    fn retain(
        &mut self,
        assembly: AcceptedSetupVerificationAssembly,
    ) -> Result<u32, CommonProofRuntimeError> {
        if !self.assemblies.is_empty() || self.next_handle == 0 {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = self
            .next_handle
            .checked_add(1)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.assemblies.insert(handle, assembly);
        Ok(handle)
    }

    fn get(
        &self,
        handle: u32,
    ) -> Result<&AcceptedSetupVerificationAssembly, CommonProofRuntimeError> {
        self.assemblies
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn get_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut AcceptedSetupVerificationAssembly, CommonProofRuntimeError> {
        self.assemblies
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn take_completed(
        &mut self,
        handle: u32,
    ) -> Result<AcceptedSetupVerificationAssembly, CommonProofRuntimeError> {
        if self.get(handle)?.public_proof_catalog.is_none() {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        self.assemblies
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(
        &mut self,
        handle: u32,
        assembly: AcceptedSetupVerificationAssembly,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.assemblies.insert(handle, assembly).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(())
    }
}

thread_local! {
    static ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY:
        RefCell<AcceptedSetupVerificationAssemblyRegistry> =
            RefCell::new(AcceptedSetupVerificationAssemblyRegistry::default());
}

fn retain_accepted_setup_verification_assembly(
    vss_recipient_authority_handle: u32,
    complaint_resolution_handle: VerifiedSetupComplaintResolutionReservationHandle,
    package: CanonicalAcceptedSetupPackage,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<u32, CommonProofRuntimeError> {
    let assembly = AcceptedSetupVerificationAssembly::new(
        vss_recipient_authority_handle,
        complaint_resolution_handle,
        package,
        verified_public_randomness,
    )?;
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY
        .with(|registry| registry.borrow_mut().retain(assembly))
}

pub(crate) fn begin_accepted_setup_verification_assembly(
    vss_recipient_authority_handle: u32,
    complaint_resolution_handle: VerifiedSetupComplaintResolutionReservationHandle,
    canonical_package_bytes: &[u8],
) -> Result<u32, CommonProofRuntimeError> {
    let package = CanonicalAcceptedSetupPackage::decode(
        canonical_package_bytes,
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    with_verified_accepted_setup_vss_public_randomness(
        vss_recipient_authority_handle,
        |verified_public_randomness| {
            retain_accepted_setup_verification_assembly(
                vss_recipient_authority_handle,
                complaint_resolution_handle,
                package,
                verified_public_randomness,
            )
            .map_err(AggregateThresholdShareRuntimeError::from)
        },
    )
    .map_err(aggregate_runtime_error)
}

pub(crate) fn with_accepted_setup_verification_sources<Output>(
    assembly_handle: u32,
    inspect: impl FnOnce(
        &CanonicalAcceptedSetupPackage,
        &VerifiedPublicRandomness,
    ) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    with_accepted_setup_verification_package(
        assembly_handle,
        |package, vss_recipient_authority_handle| {
            with_verified_accepted_setup_vss_public_randomness(
                vss_recipient_authority_handle,
                |verified_public_randomness| {
                    inspect(package, verified_public_randomness)
                        .map_err(AggregateThresholdShareRuntimeError::from)
                },
            )
            .map_err(aggregate_runtime_error)
        },
    )
}

fn aggregate_runtime_error(error: AggregateThresholdShareRuntimeError) -> CommonProofRuntimeError {
    match error {
        AggregateThresholdShareRuntimeError::Runtime(error) => error,
        _ => CommonProofRuntimeError::WrongVerificationBinding,
    }
}

pub(crate) fn with_accepted_setup_verification_package<Output>(
    assembly_handle: u32,
    inspect: impl FnOnce(&CanonicalAcceptedSetupPackage, u32) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        inspect(
            assembly
                .package
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
            assembly.vss_recipient_authority_handle,
        )
    })
}

pub(crate) struct PreparedVerifiedSameSecretTerminalSlot {
    assembly_handle: u32,
    roster_position: u16,
}

pub(crate) struct PreparedVerifiedPublicKeyShareTerminalSlot {
    assembly_handle: u32,
    roster_position: u16,
}

pub(crate) struct PreparedVerifiedCollectivePublicKeyTerminalSlot {
    assembly_handle: u32,
}

pub(crate) struct PreparedVerifiedEvaluatorKeyStoreSlot {
    assembly_handle: u32,
}

pub(crate) struct PreparedPrepackageEvaluatorSourceCatalogTransfer {
    assembly_handle: u32,
}

pub(crate) fn preflight_verified_same_secret_terminal_slot(
    assembly_handle: u32,
    roster_position: u16,
) -> Result<PreparedVerifiedSameSecretTerminalSlot, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        if usize::from(roster_position) >= usize::from(FOUNDATION_PROFILE.participant_count)
            || assembly
                .same_secret_terminals
                .contains_key(&roster_position)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedVerifiedSameSecretTerminalSlot {
            assembly_handle,
            roster_position,
        })
    })
}

pub(crate) fn commit_preflighted_verified_same_secret_terminal(
    prepared_slot: PreparedVerifiedSameSecretTerminalSlot,
    terminal: VerifiedSameSecretTerminal,
) {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_slot.assembly_handle)
            .expect("preflight retained the exact accepted-setup assembly");
        assert_eq!(terminal.roster_position(), prepared_slot.roster_position);
        assert!(
            assembly
                .same_secret_terminals
                .insert(prepared_slot.roster_position, terminal)
                .is_none(),
            "preflight reserved an empty same-secret terminal slot"
        );
    });
}

pub(crate) fn preflight_verified_public_key_share_terminal_slot(
    assembly_handle: u32,
    roster_position: u16,
) -> Result<PreparedVerifiedPublicKeyShareTerminalSlot, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        if usize::from(roster_position) >= usize::from(FOUNDATION_PROFILE.participant_count)
            || assembly
                .public_key_share_terminals
                .contains_key(&roster_position)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedVerifiedPublicKeyShareTerminalSlot {
            assembly_handle,
            roster_position,
        })
    })
}

pub(crate) fn commit_preflighted_verified_public_key_share_terminal(
    prepared_slot: PreparedVerifiedPublicKeyShareTerminalSlot,
    terminal: VerifiedPublicKeyShareTerminal,
) {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_slot.assembly_handle)
            .expect("preflight retained the exact accepted-setup assembly");
        assert_eq!(terminal.roster_position(), prepared_slot.roster_position);
        assert!(
            assembly
                .public_key_share_terminals
                .insert(prepared_slot.roster_position, terminal)
                .is_none(),
            "preflight reserved an empty public-key-share terminal slot"
        );
    });
}

pub(crate) fn preflight_verified_collective_public_key_terminal_slot(
    assembly_handle: u32,
    terminal: &VerifiedCollectivePublicKeyTerminalPreflight,
) -> Result<PreparedVerifiedCollectivePublicKeyTerminalSlot, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        if assembly.collective_public_key_terminal.is_some()
            || assembly.public_key_share_terminals.len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
            || terminal.protocol_version() != assembly.expected_protocol_version
            || terminal.suite_identifier() != assembly.expected_suite_identifier
            || terminal.ceremony_context_hash() != assembly.expected_ceremony_context_hash
            || terminal.action_context_hash() != assembly.expected_action_context_hash
            || terminal.roster_hash() != assembly.expected_roster_hash
            || terminal.setup_proof_context_hash() != assembly.expected_setup_proof_context_hash
            || terminal.ordered_public_key_share_roots().len()
                != usize::from(FOUNDATION_PROFILE.participant_count)
            || terminal
                .ordered_public_key_share_roots()
                .iter()
                .enumerate()
                .any(|(roster_index, expected_root)| {
                    u16::try_from(roster_index)
                        .ok()
                        .and_then(|roster_position| {
                            assembly.public_key_share_terminals.get(&roster_position)
                        })
                        .is_none_or(|public_key_share| {
                            public_key_share.public_key_share_root() != *expected_root
                        })
                })
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedVerifiedCollectivePublicKeyTerminalSlot { assembly_handle })
    })
}

pub(crate) fn with_verified_same_secret_terminal<Output>(
    assembly_handle: u32,
    roster_position: u16,
    inspect: impl FnOnce(&VerifiedSameSecretTerminal) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        inspect(
            assembly
                .same_secret_terminals
                .get(&roster_position)
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
        )
    })
}

pub(crate) fn commit_preflighted_verified_collective_public_key_terminal(
    prepared_slot: PreparedVerifiedCollectivePublicKeyTerminalSlot,
    terminal: VerifiedCollectivePublicKeyTerminal,
) {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_slot.assembly_handle)
            .expect("preflight retained the exact accepted-setup assembly");
        assert!(
            assembly
                .collective_public_key_terminal
                .replace(terminal)
                .is_none()
        );
    });
}

fn preflight_prepackage_evaluator_source_catalog_transfer(
    assembly_handle: u32,
    catalog: &VerifiedAcceptedSetupEvaluatorSourceCatalog,
    aggregate: &VerifiedRelinearizationAggregateMaterial,
) -> Result<PreparedPrepackageEvaluatorSourceCatalogTransfer, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        if assembly.evaluator_source_catalog.is_some()
            || assembly.evaluator_sources_completed
            || assembly.relinearization_aggregate.is_some()
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        if catalog.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || !assembly.evaluator_catalog_matches_expected_context(catalog)
            || aggregate.protocol_version() != catalog.protocol_version()
            || aggregate.suite_identifier() != catalog.suite_identifier()
            || aggregate.ceremony_context_hash() != catalog.ceremony_context_hash()
            || aggregate.action_context_hash() != catalog.action_context_hash()
            || aggregate.roster_hash() != catalog.roster_hash()
            || aggregate.setup_proof_context_hash() != catalog.setup_proof_context_hash()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedPrepackageEvaluatorSourceCatalogTransfer { assembly_handle })
    })
}

fn commit_prepackage_evaluator_source_catalog_transfer(
    prepared_transfer: PreparedPrepackageEvaluatorSourceCatalogTransfer,
    catalog: VerifiedAcceptedSetupEvaluatorSourceCatalog,
    aggregate: VerifiedRelinearizationAggregateMaterial,
) {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_transfer.assembly_handle)
            .expect("preflight retained the exact accepted-setup assembly");
        assert!(!assembly.evaluator_sources_completed);
        assert!(assembly.evaluator_source_catalog.replace(catalog).is_none());
        assert!(
            assembly
                .relinearization_aggregate
                .replace(aggregate)
                .is_none()
        );
    });
}

pub(crate) fn transfer_completed_prepackage_evaluator_source_catalog(
    assembly_handle: u32,
    prepackage_catalog_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let prepared_transfer = with_completed_prepackage_evaluator_source_catalog(
        prepackage_catalog_handle,
        |catalog, aggregate| {
            preflight_prepackage_evaluator_source_catalog_transfer(
                assembly_handle,
                catalog,
                aggregate,
            )
        },
    )?;
    let (catalog, aggregate) =
        consume_completed_prepackage_evaluator_source_catalog(prepackage_catalog_handle)?;
    commit_prepackage_evaluator_source_catalog_transfer(prepared_transfer, catalog, aggregate);
    Ok(())
}

pub(crate) fn preflight_verified_evaluator_key_store_slot(
    assembly_handle: u32,
) -> Result<PreparedVerifiedEvaluatorKeyStoreSlot, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        if !assembly.evaluator_sources_completed
            || assembly.evaluator_source_catalog.is_none()
            || assembly.verified_evaluator_key_store.is_some()
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        Ok(PreparedVerifiedEvaluatorKeyStoreSlot { assembly_handle })
    })
}

pub(crate) fn commit_preflighted_verified_evaluator_key_store(
    prepared_slot: PreparedVerifiedEvaluatorKeyStoreSlot,
    store: VerifiedEvaluatorKeyStore,
) {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_slot.assembly_handle)
            .expect("preflight retained the exact accepted-setup assembly");
        assert!(
            assembly
                .verified_evaluator_key_store
                .replace(store)
                .is_none()
        );
    });
}

pub(crate) fn complete_accepted_setup_evaluator_source_catalog(
    assembly_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .get_mut(assembly_handle)?
            .complete_evaluator_source_catalog()
    })
}

pub(crate) fn complete_accepted_setup_public_proof_catalog(
    assembly_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .get_mut(assembly_handle)?
            .complete_public_proof_catalog()
    })
}

fn take_completed_accepted_setup_verification_assembly(
    assembly_handle: u32,
) -> Result<AcceptedSetupVerificationAssembly, CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY
        .with(|registry| registry.borrow_mut().take_completed(assembly_handle))
}

fn restore_accepted_setup_verification_assembly(
    assembly_handle: u32,
    assembly: AcceptedSetupVerificationAssembly,
) -> Result<(), CommonProofRuntimeError> {
    ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY
        .with(|registry| registry.borrow_mut().restore(assembly_handle, assembly))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn finalize_completed_accepted_setup_verification_assembly(
    assembly_handle: u32,
    state_session_handle: u32,
    state_session_capability: &[u8],
    ordered_commitment_reservation_handles: &[u32],
    terminal_package_reservation_handles: &[u32],
) -> Result<VerifiedAcceptedSetupAuthorityHandle, u32> {
    let mut assembly = take_completed_accepted_setup_verification_assembly(assembly_handle)
        .map_err(runtime_error_status)?;
    let vss_qualification = match consume_verified_accepted_setup_vss_qualification(
        assembly.vss_recipient_authority_handle,
    ) {
        Ok(qualification) => qualification,
        Err(error) => {
            restore_accepted_setup_verification_assembly(assembly_handle, assembly)
                .map_err(runtime_error_status)?;
            return Err(aggregate_threshold_share_runtime_error_status(error));
        }
    };
    let public_proof_catalog = assembly
        .public_proof_catalog
        .take()
        .expect("the completed assembly owns its public proof catalog");
    let package = assembly
        .package
        .take()
        .expect("the completed assembly owns its canonical package");
    let finalization_input = RefCell::new(Some(VerifiedAcceptedSetupFinalizationInput {
        package,
        vss_qualification,
        public_proof_catalog,
        complaint_resolution_handle: assembly.complaint_resolution_handle,
    }));
    let result = finalize_verified_accepted_setup(
        state_session_handle,
        state_session_capability,
        ordered_commitment_reservation_handles,
        terminal_package_reservation_handles,
        &finalization_input,
    );
    match result {
        Ok(authority_handle) => Ok(authority_handle),
        Err(status) => {
            let VerifiedAcceptedSetupFinalizationInput {
                package,
                vss_qualification,
                public_proof_catalog,
                complaint_resolution_handle: _,
            } = finalization_input
                .into_inner()
                .expect("a failed finalization leaves every exact source unconsumed");
            assembly.package = Some(package);
            assembly.public_proof_catalog = Some(public_proof_catalog);
            restore_verified_accepted_setup_vss_qualification(
                assembly.vss_recipient_authority_handle,
                vss_qualification,
            )
            .expect("a failed finalization restores the exact VSS qualification");
            restore_accepted_setup_verification_assembly(assembly_handle, assembly)
                .expect("a failed finalization restores the exact verification assembly");
            Err(status)
        }
    }
}

pub(crate) fn cancel_accepted_setup_verification_assembly(
    assembly_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let assembly = ACCEPTED_SETUP_VERIFICATION_ASSEMBLY_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .assemblies
            .remove(&assembly_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    })?;
    restore_verified_setup_complaint_resolution(&assembly.complaint_resolution_handle)
        .map_err(|_| CommonProofRuntimeError::UnknownOrStaleHandle)
}

unsafe fn ffi_input<'input>(
    pointer: *const u8,
    byte_length: usize,
) -> Result<&'input [u8], CommonProofRuntimeError> {
    if pointer.is_null() || byte_length == 0 {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    Ok(unsafe { slice::from_raw_parts(pointer, byte_length) })
}

fn decode_u32_handles(bytes: &[u8]) -> Result<Vec<u32>, CommonProofRuntimeError> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(size_of::<u32>()) {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    bytes
        .chunks_exact(size_of::<u32>())
        .map(|chunk| {
            chunk
                .try_into()
                .map(u32::from_le_bytes)
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        })
        .collect()
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

/// Cancels one incomplete or complete verification assembly. The completed
/// VSS authority remains independently owned until it is finalized or
/// explicitly discarded.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_verification_cancel(assembly_handle: u32) -> u32 {
    cancel_accepted_setup_verification_assembly(assembly_handle)
        .map_or_else(runtime_error_status, |()| 0)
}

/// Releases one completed accepted-setup authority and all still-owned
/// participant-facing facets. The branded browser owner calls this exactly
/// once; a stale identifier is refused rather than silently acknowledged.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_authority_release(authority_handle: u32) -> u32 {
    release_verified_accepted_setup_authority(
        VerifiedAcceptedSetupAuthorityHandle::from_identifier(authority_handle),
    )
    .map_or_else(
        |_| RefusalReason::ConsumedState.canonical_code() as u32,
        |()| 0,
    )
}

/// Transfers one completed prepackage evaluator-source catalog into the exact
/// canonical-package verification assembly. Both registries are preflighted
/// before the non-serializable source capability is consumed.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_verification_transfer_prepackage_evaluator_sources(
    assembly_handle: u32,
    prepackage_catalog_handle: u32,
) -> u32 {
    transfer_completed_prepackage_evaluator_source_catalog(
        assembly_handle,
        prepackage_catalog_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

/// Freezes the exact participant evaluator-source inventory after every
/// selected relinearization and Galois family terminal has been inserted.
/// The transition preflights the complete join before consuming any source.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_verification_complete_evaluator_sources(
    assembly_handle: u32,
) -> u32 {
    complete_accepted_setup_evaluator_source_catalog(assembly_handle)
        .map_or_else(runtime_error_status, |()| 0)
}

/// Freezes the exact public-proof catalog after the complete-list evaluator
/// proof has inserted its verified store. No typed terminal is consumed until
/// the package descriptor inventory and every cross-family join preflight.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_accepted_setup_verification_complete_public_proofs(
    assembly_handle: u32,
) -> u32 {
    complete_accepted_setup_public_proof_catalog(assembly_handle)
        .map_or_else(runtime_error_status, |()| 0)
}

/// Atomically publishes one completed accepted setup against the exact
/// reset-safe state reservations retained by the state verifier.
///
/// # Safety
///
/// Every input pointer must name its declared readable range. Reservation
/// handle arrays contain little-endian `u32` values. A non-null status pointer
/// must name one writable `u32`.
#[unsafe(no_mangle)]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sealed_lattice_accepted_setup_verification_finalize(
    assembly_handle: u32,
    state_session_handle: u32,
    state_session_capability_pointer: *const u8,
    state_session_capability_byte_length: usize,
    ordered_commitment_reservation_handles_pointer: *const u8,
    ordered_commitment_reservation_handles_byte_length: usize,
    terminal_package_reservation_handles_pointer: *const u8,
    terminal_package_reservation_handles_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result: Result<VerifiedAcceptedSetupAuthorityHandle, u32> = (|| {
        let state_session_capability = unsafe {
            ffi_input(
                state_session_capability_pointer,
                state_session_capability_byte_length,
            )
        }
        .map_err(runtime_error_status)?;
        let ordered_commitment_reservation_handle_bytes = unsafe {
            ffi_input(
                ordered_commitment_reservation_handles_pointer,
                ordered_commitment_reservation_handles_byte_length,
            )
        }
        .map_err(runtime_error_status)?;
        let ordered_commitment_reservation_handles =
            decode_u32_handles(ordered_commitment_reservation_handle_bytes)
                .map_err(runtime_error_status)?;
        let terminal_package_reservation_handle_bytes = unsafe {
            ffi_input(
                terminal_package_reservation_handles_pointer,
                terminal_package_reservation_handles_byte_length,
            )
        }
        .map_err(runtime_error_status)?;
        let terminal_package_reservation_handles =
            decode_u32_handles(terminal_package_reservation_handle_bytes)
                .map_err(runtime_error_status)?;
        finalize_completed_accepted_setup_verification_assembly(
            assembly_handle,
            state_session_handle,
            state_session_capability,
            &ordered_commitment_reservation_handles,
            &terminal_package_reservation_handles,
        )
    })();
    match result {
        Ok(authority_handle) => {
            unsafe { write_status(status_pointer, 0) };
            authority_handle.identifier()
        }
        Err(status) => {
            unsafe { write_status(status_pointer, status) };
            0
        }
    }
}
