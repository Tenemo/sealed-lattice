use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    bgv::proof_suite::{
        AggregateThresholdShareRuntimeError, CommonProofRuntimeError,
        VerifiedGaloisSourceMaterialBatch, VerifiedRelinearizationAggregateMaterial,
        VerifiedRelinearizationSourceMaterial, runtime_error_status,
        with_verified_accepted_setup_vss_public_randomness,
    },
    foundation::FOUNDATION_PROFILE,
};

use super::{
    evaluator_source::{
        VerifiedAcceptedSetupEvaluatorSourceCatalog,
        VerifiedAcceptedSetupParticipantEvaluatorSource,
    },
    verified_public_randomness::VerifiedPublicRandomness,
};

/// Non-serializable source authority used only before the canonical accepted
/// package can contain its genuine evaluator proof descriptor. Its catalog is
/// built exclusively from positively verified source-family capabilities.
struct PrepackageEvaluatorSourceCatalogAssembly {
    expected_protocol_version: u16,
    expected_suite_identifier: [u8; 64],
    expected_ceremony_context_hash: [u8; 64],
    expected_action_context_hash: [u8; 64],
    expected_ordered_participant_identities: Box<[[u8; 64]]>,
    expected_manifest_hash: [u8; 64],
    expected_roster_hash: [u8; 64],
    expected_setup_proof_context_hash: [u8; 64],
    relinearization_aggregate: Option<VerifiedRelinearizationAggregateMaterial>,
    relinearization_sources: BTreeMap<u16, VerifiedRelinearizationSourceMaterial>,
    galois_sources: BTreeMap<u16, VerifiedGaloisSourceMaterialBatch>,
    evaluator_source_catalog: Option<VerifiedAcceptedSetupEvaluatorSourceCatalog>,
}

impl PrepackageEvaluatorSourceCatalogAssembly {
    fn new(verified_public_randomness: &VerifiedPublicRandomness) -> Self {
        let context = verified_public_randomness.context();
        Self {
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
            relinearization_aggregate: None,
            relinearization_sources: BTreeMap::new(),
            galois_sources: BTreeMap::new(),
            evaluator_source_catalog: None,
        }
    }

    fn require_collecting(&self) -> Result<(), CommonProofRuntimeError> {
        if self.evaluator_source_catalog.is_some() {
            Err(CommonProofRuntimeError::WrongOperationPhase)
        } else {
            Ok(())
        }
    }

    fn catalog_matches_expected_context(
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

    fn complete(&mut self) -> Result<(), CommonProofRuntimeError> {
        self.require_collecting()?;
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if self.relinearization_aggregate.is_none()
            || self.relinearization_sources.len() != participant_count
            || self.galois_sources.len() != participant_count
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }

        let mut borrowed_ordered_sources = Vec::new();
        borrowed_ordered_sources
            .try_reserve_exact(participant_count)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            borrowed_ordered_sources.push((
                self.relinearization_sources
                    .get(&roster_position)
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?,
                self.galois_sources
                    .get(&roster_position)
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?,
            ));
        }
        let (first_relinearization, first_galois) = borrowed_ordered_sources
            .first()
            .copied()
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let aggregate = self
            .relinearization_aggregate
            .as_ref()
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        if first_relinearization.protocol_version() != self.expected_protocol_version
            || first_relinearization.suite_identifier() != self.expected_suite_identifier
            || first_relinearization.ceremony_context_hash() != self.expected_ceremony_context_hash
            || first_relinearization.action_context_hash() != self.expected_action_context_hash
            || first_relinearization.setup_proof_context_hash()
                != self.expected_setup_proof_context_hash
            || first_galois.protocol_version() != self.expected_protocol_version
            || first_galois.suite_identifier() != self.expected_suite_identifier
            || first_galois.ceremony_context_hash() != self.expected_ceremony_context_hash
            || first_galois.action_context_hash() != self.expected_action_context_hash
            || first_galois.setup_proof_context_hash() != self.expected_setup_proof_context_hash
            || aggregate.protocol_version() != self.expected_protocol_version
            || aggregate.suite_identifier() != self.expected_suite_identifier
            || aggregate.ceremony_context_hash() != self.expected_ceremony_context_hash
            || aggregate.action_context_hash() != self.expected_action_context_hash
            || aggregate.roster_hash() != self.expected_roster_hash
            || aggregate.setup_proof_context_hash() != self.expected_setup_proof_context_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let preflight =
            VerifiedAcceptedSetupEvaluatorSourceCatalog::preflight_from_verified_participant_sources(
                &self.expected_ordered_participant_identities,
                self.expected_manifest_hash,
                self.expected_roster_hash,
                aggregate,
                &borrowed_ordered_sources,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        drop(borrowed_ordered_sources);

        let mut ordered_participants = Vec::new();
        ordered_participants
            .try_reserve_exact(participant_count)
            .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            let relinearization = self
                .relinearization_sources
                .remove(&roster_position)
                .expect("borrowed preflight established the exact relinearization source");
            let galois = self
                .galois_sources
                .remove(&roster_position)
                .expect("borrowed preflight established the exact Galois source");
            ordered_participants.push(
                VerifiedAcceptedSetupParticipantEvaluatorSource::from_verified_sources(
                    relinearization,
                    galois,
                ),
            );
        }
        let catalog =
            VerifiedAcceptedSetupEvaluatorSourceCatalog::from_preflighted_participant_sources(
                preflight,
                ordered_participants,
            );
        assert!(self.catalog_matches_expected_context(&catalog));
        self.evaluator_source_catalog = Some(catalog);
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedPrepackageRelinearizationAggregateSlot {
    assembly_handle: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedPrepackageRelinearizationSourceSlot {
    assembly_handle: u32,
    roster_position: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct PreparedPrepackageGaloisSourceSlot {
    assembly_handle: u32,
    roster_position: u16,
}

struct PrepackageEvaluatorSourceCatalogRegistry {
    next_handle: u32,
    assemblies: BTreeMap<u32, PrepackageEvaluatorSourceCatalogAssembly>,
}

impl Default for PrepackageEvaluatorSourceCatalogRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            assemblies: BTreeMap::new(),
        }
    }
}

impl PrepackageEvaluatorSourceCatalogRegistry {
    fn retain(
        &mut self,
        assembly: PrepackageEvaluatorSourceCatalogAssembly,
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
    ) -> Result<&PrepackageEvaluatorSourceCatalogAssembly, CommonProofRuntimeError> {
        self.assemblies
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn get_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut PrepackageEvaluatorSourceCatalogAssembly, CommonProofRuntimeError> {
        self.assemblies
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }
}

thread_local! {
    static PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY:
        RefCell<PrepackageEvaluatorSourceCatalogRegistry> =
            RefCell::new(PrepackageEvaluatorSourceCatalogRegistry::default());
}

fn aggregate_runtime_error(error: AggregateThresholdShareRuntimeError) -> CommonProofRuntimeError {
    match error {
        AggregateThresholdShareRuntimeError::Runtime(error) => error,
        _ => CommonProofRuntimeError::WrongVerificationBinding,
    }
}

pub(crate) fn begin_prepackage_evaluator_source_catalog(
    vss_recipient_authority_handle: u32,
) -> Result<u32, CommonProofRuntimeError> {
    if vss_recipient_authority_handle == 0 {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    with_verified_accepted_setup_vss_public_randomness(
        vss_recipient_authority_handle,
        |verified_public_randomness| {
            PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .retain(PrepackageEvaluatorSourceCatalogAssembly::new(
                        verified_public_randomness,
                    ))
                    .map_err(AggregateThresholdShareRuntimeError::from)
            })
        },
    )
    .map_err(aggregate_runtime_error)
}

pub(crate) fn preflight_prepackage_relinearization_aggregate_slot(
    assembly_handle: u32,
) -> Result<PreparedPrepackageRelinearizationAggregateSlot, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        if assembly.relinearization_aggregate.is_some() {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedPrepackageRelinearizationAggregateSlot { assembly_handle })
    })
}

pub(crate) fn commit_prepackage_relinearization_aggregate(
    prepared_slot: PreparedPrepackageRelinearizationAggregateSlot,
    aggregate: VerifiedRelinearizationAggregateMaterial,
) {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_slot.assembly_handle)
            .expect("preflight retained the exact prepackage source assembly");
        assert!(
            assembly
                .relinearization_aggregate
                .replace(aggregate)
                .is_none()
        );
    });
}

pub(crate) fn preflight_prepackage_relinearization_source_slot(
    assembly_handle: u32,
    roster_position: u16,
) -> Result<PreparedPrepackageRelinearizationSourceSlot, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        if usize::from(roster_position) >= usize::from(FOUNDATION_PROFILE.participant_count)
            || assembly
                .relinearization_sources
                .contains_key(&roster_position)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedPrepackageRelinearizationSourceSlot {
            assembly_handle,
            roster_position,
        })
    })
}

pub(crate) fn with_prepackage_relinearization_aggregate<Output>(
    assembly_handle: u32,
    inspect: impl FnOnce(
        &VerifiedRelinearizationAggregateMaterial,
    ) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        inspect(
            assembly
                .relinearization_aggregate
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
        )
    })
}

pub(crate) fn commit_prepackage_relinearization_source(
    prepared_slot: PreparedPrepackageRelinearizationSourceSlot,
    source: VerifiedRelinearizationSourceMaterial,
) {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_slot.assembly_handle)
            .expect("preflight retained the exact prepackage source assembly");
        assert_eq!(source.roster_position(), prepared_slot.roster_position);
        assert!(
            assembly
                .relinearization_sources
                .insert(prepared_slot.roster_position, source)
                .is_none()
        );
    });
}

pub(crate) fn preflight_prepackage_galois_source_slot(
    assembly_handle: u32,
    roster_position: u16,
) -> Result<PreparedPrepackageGaloisSourceSlot, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        if usize::from(roster_position) >= usize::from(FOUNDATION_PROFILE.participant_count)
            || assembly.galois_sources.contains_key(&roster_position)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedPrepackageGaloisSourceSlot {
            assembly_handle,
            roster_position,
        })
    })
}

pub(crate) fn commit_prepackage_galois_source(
    prepared_slot: PreparedPrepackageGaloisSourceSlot,
    source: VerifiedGaloisSourceMaterialBatch,
) {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_slot.assembly_handle)
            .expect("preflight retained the exact prepackage source assembly");
        assert_eq!(source.roster_position(), prepared_slot.roster_position);
        assert!(
            assembly
                .galois_sources
                .insert(prepared_slot.roster_position, source)
                .is_none()
        );
    });
}

pub(crate) fn complete_prepackage_evaluator_source_catalog(
    assembly_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY
        .with(|registry| registry.borrow_mut().get_mut(assembly_handle)?.complete())
}

pub(crate) fn with_completed_prepackage_evaluator_source_catalog<Output>(
    assembly_handle: u32,
    inspect: impl FnOnce(
        &VerifiedAcceptedSetupEvaluatorSourceCatalog,
        &VerifiedRelinearizationAggregateMaterial,
    ) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        inspect(
            assembly
                .evaluator_source_catalog
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
            assembly
                .relinearization_aggregate
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
        )
    })
}

pub(super) fn consume_completed_prepackage_evaluator_source_catalog(
    assembly_handle: u32,
) -> Result<
    (
        VerifiedAcceptedSetupEvaluatorSourceCatalog,
        VerifiedRelinearizationAggregateMaterial,
    ),
    CommonProofRuntimeError,
> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let mut assembly = registry
            .assemblies
            .remove(&assembly_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if assembly.evaluator_source_catalog.is_none()
            || assembly.relinearization_aggregate.is_none()
        {
            registry.assemblies.insert(assembly_handle, assembly);
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let catalog = assembly
            .evaluator_source_catalog
            .take()
            .expect("completed prepackage catalog presence was established");
        let aggregate = assembly
            .relinearization_aggregate
            .take()
            .expect("completed prepackage aggregate presence was established");
        Ok((catalog, aggregate))
    })
}

pub(crate) fn cancel_prepackage_evaluator_source_catalog(
    assembly_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .assemblies
            .remove(&assembly_handle)
            .map(|_| ())
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    })
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

/// Begins one process-local source catalog from the completed VSS/public-
/// randomness authority. No transported catalog fields are accepted.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_prepackage_evaluator_source_catalog_begin(
    vss_recipient_authority_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match begin_prepackage_evaluator_source_catalog(vss_recipient_authority_handle) {
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

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_prepackage_evaluator_source_catalog_complete(
    assembly_handle: u32,
) -> u32 {
    complete_prepackage_evaluator_source_catalog(assembly_handle)
        .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_prepackage_evaluator_source_catalog_cancel(
    assembly_handle: u32,
) -> u32 {
    cancel_prepackage_evaluator_source_catalog(assembly_handle)
        .map_or_else(runtime_error_status, |()| 0)
}
