use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    bgv::proof_suite::{
        AggregateThresholdShareRuntimeError, CommonProofRelationPlanCapability,
        CommonProofRuntimeError,
        SelectedEvaluatorEntryPosition, SelectedEvaluatorStoreSource,
        SelectedEvaluatorStoreSourceCatalog, VerifiedGaloisSourceMaterialBatch,
        VerifiedCommonProofStatementSource, VerifiedEvaluatorAuxiliaryRoot,
        VerifiedEvaluatorRuntimeRoot, VerifiedRelinearizationAggregateMaterial,
        VerifiedRelinearizationSourceMaterial,
        VerifiedGaloisSourceMaterialBatchPreflight,
        bind_generated_common_proofs_to_verified_statement_sources,
        decode_selected_application_statement,
        preflight_generated_common_proof_pending_statement, runtime_error_status,
        retire_generated_common_proof_capabilities,
        selected_evaluator_aggregate_entry_roots_in_order,
        selected_evaluator_entry_positions,
        selected_evaluator_galois_entry_positions,
        selected_galois_key_share_batch_schedule,
        selected_proof_runtime_limits, selected_relation_plan_check_context,
        selected_relation_plans,
        verified_application_statement_hash,
        with_verified_accepted_setup_vss_public_randomness,
    },
    foundation::{
        CanonicalDecodeLimits, CanonicalItemType, FOUNDATION_PROFILE, Hash512,
        ProofApplicationBinding, ProofApplicationSlot, ProofApplicationSlotCeilings,
        ProofObjectHeader, RefusalReason, StreamDescriptor,
    },
};

use super::{
    evaluator_source::{
        VerifiedAcceptedSetupEvaluatorSourceCatalog,
        VerifiedAcceptedSetupParticipantEvaluatorSource,
    },
    generation_authority::SetupGeneratedGaloisSourceAuthority,
    canonical_package::CanonicalAcceptedSetupPackage,
    verification_assembly::with_accepted_setup_verification_sources,
    verified_public_randomness::VerifiedPublicRandomness,
};

/// Non-serializable source authority used only before the canonical accepted
/// package can contain its genuine evaluator proof descriptor. Generated
/// Galois sources are retained in a distinct authority used only for proving;
/// the final catalog is still built exclusively from positively verified
/// source-family capabilities.
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
    generated_galois_sources: BTreeMap<u16, SetupGeneratedGaloisSourceAuthority>,
    pending_galois_proofs: BTreeMap<u16, PendingGeneratedCommonProof>,
    package_bound_galois_statement_sources:
        BTreeMap<u16, VerifiedCommonProofStatementSource>,
    pending_evaluator_proof: Option<PendingGeneratedEvaluatorCommonProof>,
    package_bound_evaluator_statement_source: Option<VerifiedCommonProofStatementSource>,
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
            generated_galois_sources: BTreeMap::new(),
            pending_galois_proofs: BTreeMap::new(),
            package_bound_galois_statement_sources: BTreeMap::new(),
            pending_evaluator_proof: None,
            package_bound_evaluator_statement_source: None,
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

    fn require_generation_sources_complete(&self) -> Result<(), CommonProofRuntimeError> {
        self.require_collecting()?;
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if self.relinearization_aggregate.is_none()
            || self.relinearization_sources.len() != participant_count
            || self.generated_galois_sources.len() != participant_count
            || self.pending_galois_proofs.len() != participant_count
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        let [expected_batch_schedule_position] = selected_galois_key_share_batch_schedule();
        let expected_galois_positions = selected_evaluator_galois_entry_positions()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let mut expected_galois_auxiliary_roots: Option<&[VerifiedEvaluatorAuxiliaryRoot]> = None;
        for roster_position in 0..FOUNDATION_PROFILE.participant_count {
            let relinearization = self
                .relinearization_sources
                .get(&roster_position)
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let galois = self
                .generated_galois_sources
                .get(&roster_position)
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let expected_participant_identity = self
                .expected_ordered_participant_identities
                .get(usize::from(roster_position))
                .copied()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            if galois.protocol_version() != self.expected_protocol_version
                || galois.suite_identifier() != self.expected_suite_identifier
                || galois.ceremony_context_hash() != self.expected_ceremony_context_hash
                || galois.action_context_hash() != self.expected_action_context_hash
                || galois.roster_hash() != self.expected_roster_hash
                || galois.setup_proof_context_hash() != self.expected_setup_proof_context_hash
                || galois.participant_identity() != expected_participant_identity
                || galois.roster_position() != roster_position
                || galois.batch_schedule_position() != expected_batch_schedule_position
                || galois.anchor_commitment_roots()
                    != relinearization.anchor_commitment_roots()
                || galois.ordered_components().len() != expected_galois_positions.len()
                || galois.ordered_auxiliary_roots().len() != expected_galois_positions.len()
                || galois
                    .ordered_auxiliary_roots()
                    .iter()
                    .zip(&expected_galois_positions)
                    .any(|(root, expected_position)| root.position() != *expected_position)
                || galois
                    .ordered_components()
                    .iter()
                    .zip(&expected_galois_positions)
                    .any(|(component, expected_position)| {
                        component.evaluator_position() != *expected_position
                    })
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            if expected_galois_auxiliary_roots
                .is_some_and(|expected| expected != galois.ordered_auxiliary_roots())
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            expected_galois_auxiliary_roots = Some(galois.ordered_auxiliary_roots());
        }
        Ok(())
    }

    fn ordered_generation_auxiliary_roots(
        &self,
    ) -> Result<Vec<VerifiedEvaluatorAuxiliaryRoot>, CommonProofRuntimeError> {
        self.require_generation_sources_complete()?;
        let relinearization_root =
            VerifiedEvaluatorAuxiliaryRoot::from_verified_relinearization_aggregate_material(
                self.relinearization_aggregate
                    .as_ref()
                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let first_galois_source = self
            .generated_galois_sources
            .get(&0)
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        selected_evaluator_entry_positions(FOUNDATION_PROFILE.option_count)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
            .into_iter()
            .map(|position| {
                if relinearization_root.position() == position {
                    return Ok(relinearization_root.clone());
                }
                first_galois_source
                    .ordered_auxiliary_roots()
                    .iter()
                    .find(|root| root.position() == position)
                    .cloned()
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)
            })
            .collect()
    }

    fn complete(&mut self) -> Result<(), CommonProofRuntimeError> {
        self.require_collecting()?;
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        if self.relinearization_aggregate.is_none()
            || self.relinearization_sources.len() != participant_count
            || self.galois_sources.len() != participant_count
            || self
                .pending_galois_proofs
                .values()
                .any(|proof| proof.generated_proof_handle.is_some())
            || !self.package_bound_galois_statement_sources.is_empty()
            || self
                .pending_evaluator_proof
                .as_ref()
                .is_none_or(|proof| proof.generated_proof_handle.is_some())
            || self.package_bound_evaluator_statement_source.is_some()
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

impl SelectedEvaluatorStoreSourceCatalog for PrepackageEvaluatorSourceCatalogAssembly {
    fn protocol_version(&self) -> u16 {
        self.expected_protocol_version
    }

    fn suite_identifier(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.expected_suite_identifier
    }

    fn ceremony_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.expected_ceremony_context_hash
    }

    fn action_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.expected_action_context_hash
    }

    fn manifest_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.expected_manifest_hash
    }

    fn roster_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.expected_roster_hash
    }

    fn setup_proof_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.expected_setup_proof_context_hash
    }

    fn component_source(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Result<Option<SelectedEvaluatorStoreSource>, RefusalReason> {
        if let Some(relinearization) = self.relinearization_sources.get(&roster_position)
            && relinearization.evaluator_position() == evaluator_position
        {
            let material = relinearization.material();
            return Ok(Some(SelectedEvaluatorStoreSource::from_authenticated_authority(
                material.topology().clone(),
                material.material_root().into_bytes(),
                material.stream_descriptor().clone(),
                material.begin_authenticated_readback()?,
            )));
        }
        let component = self
            .generated_galois_sources
            .get(&roster_position)
            .and_then(|source| {
                source
                    .ordered_components()
                    .iter()
                    .find(|component| component.evaluator_position() == evaluator_position)
            });
        let Some(component) = component else {
            return Ok(None);
        };
        Ok(Some(SelectedEvaluatorStoreSource::from_authenticated_authority(
            component.topology().clone(),
            component.material_root().into_bytes(),
            component.stream_descriptor().clone(),
            component.begin_authenticated_readback()?,
        )))
    }

    fn component_root(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<[u8; Hash512::BYTE_LENGTH]> {
        if let Some(relinearization) = self.relinearization_sources.get(&roster_position)
            && relinearization.evaluator_position() == evaluator_position
        {
            return Some(relinearization.contribution_root());
        }
        self.generated_galois_sources
            .get(&roster_position)?
            .ordered_components()
            .iter()
            .find(|component| component.evaluator_position() == evaluator_position)
            .map(|component| component.contribution_root())
    }

    fn component_public_polynomial_context_hash(
        &self,
        roster_position: u16,
        evaluator_position: SelectedEvaluatorEntryPosition,
    ) -> Option<[u8; Hash512::BYTE_LENGTH]> {
        if let Some(relinearization) = self.relinearization_sources.get(&roster_position)
            && relinearization.evaluator_position() == evaluator_position
        {
            return Some(relinearization.public_polynomial_context_hash());
        }
        self.generated_galois_sources
            .get(&roster_position)?
            .ordered_components()
            .iter()
            .find(|component| component.evaluator_position() == evaluator_position)
            .map(|component| component.public_polynomial_context_hash())
    }
}

struct PendingGeneratedCommonProof {
    generated_proof_handle: Option<u32>,
    stream_descriptor: StreamDescriptor,
}

struct PendingGeneratedEvaluatorCommonProof {
    generated_proof_handle: Option<u32>,
    stream_descriptor: StreamDescriptor,
    canonical_application_statement_bytes: Box<[u8]>,
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

pub(crate) struct PreparedPrepackageGeneratedGaloisSourceSlot {
    assembly_handle: u32,
    roster_position: u16,
    pending_proof: PendingGeneratedCommonProof,
}

pub(crate) struct PreparedPrepackageGeneratedEvaluatorProofSlot {
    assembly_handle: u32,
    pending_proof: PendingGeneratedEvaluatorCommonProof,
}

struct PreparedPackageBoundStatementSource {
    roster_position: Option<u16>,
    generated_proof_handle: u32,
    statement_source: VerifiedCommonProofStatementSource,
}

pub(crate) struct PreparedPrepackageGeneratedProofPackageBinding {
    prepackage_assembly_handle: u32,
    ordered_sources: Vec<PreparedPackageBoundStatementSource>,
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

pub(crate) fn with_prepackage_relinearization_source<Output>(
    assembly_handle: u32,
    roster_position: u16,
    inspect: impl FnOnce(
        &VerifiedRelinearizationSourceMaterial,
    ) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        inspect(
            assembly
                .relinearization_sources
                .get(&roster_position)
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
        )
    })
}

pub(crate) fn with_prepackage_generated_galois_source<Output>(
    assembly_handle: u32,
    roster_position: u16,
    inspect: impl FnOnce(
        &SetupGeneratedGaloisSourceAuthority,
    ) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        inspect(
            assembly
                .generated_galois_sources
                .get(&roster_position)
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
    source: &VerifiedGaloisSourceMaterialBatchPreflight,
) -> Result<PreparedPrepackageGaloisSourceSlot, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        let roster_position = source.roster_position();
        let generated_source = assembly
            .generated_galois_sources
            .get(&roster_position)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let pending_proof = assembly
            .pending_galois_proofs
            .get(&roster_position)
            .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
        let expected_statement_hash = verified_application_statement_hash(
            generated_source.protocol_version(),
            generated_source.suite_identifier(),
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
            generated_source.canonical_application_statement_bytes(),
        );
        if usize::from(roster_position) >= usize::from(FOUNDATION_PROFILE.participant_count)
            || assembly.galois_sources.contains_key(&roster_position)
            || pending_proof.generated_proof_handle.is_some()
            || assembly
                .package_bound_galois_statement_sources
                .contains_key(&roster_position)
            || source.protocol_version() != generated_source.protocol_version()
            || source.suite_identifier() != generated_source.suite_identifier()
            || source.ceremony_context_hash() != generated_source.ceremony_context_hash()
            || source.action_context_hash() != generated_source.action_context_hash()
            || source.roster_hash() != generated_source.roster_hash()
            || source.setup_proof_context_hash()
                != generated_source.setup_proof_context_hash()
            || source.participant_identity() != generated_source.participant_identity()
            || source.batch_schedule_position() != generated_source.batch_schedule_position()
            || source.anchor_commitment_roots()
                != generated_source.anchor_commitment_roots()
            || source.application_statement_hash() != expected_statement_hash
            || source.proof_stream_descriptor() != &pending_proof.stream_descriptor
            || source.ordered_auxiliary_roots() != generated_source.ordered_auxiliary_roots()
            || source.ordered_component_bindings().len()
                != generated_source.ordered_components().len()
            || source
                .ordered_component_bindings()
                .iter()
                .zip(generated_source.ordered_components())
                .any(|(verified_component, generated_component)| {
                    verified_component.evaluator_position()
                        != generated_component.evaluator_position()
                        || verified_component.public_polynomial_context_hash()
                            != generated_component.public_polynomial_context_hash()
                        || verified_component.contribution_root()
                            != generated_component.contribution_root()
                        || verified_component.material_root()
                            != generated_component.material_root()
                        || verified_component.topology() != generated_component.topology()
                        || verified_component.stream_descriptor()
                            != generated_component.stream_descriptor()
                })
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedPrepackageGaloisSourceSlot {
            assembly_handle,
            roster_position,
        })
    })
}

pub(crate) fn preflight_prepackage_generated_galois_source_slot(
    assembly_handle: u32,
    generated_proof_handle: u32,
    source: &SetupGeneratedGaloisSourceAuthority,
) -> Result<PreparedPrepackageGeneratedGaloisSourceSlot, CommonProofRuntimeError> {
    let stream_descriptor = preflight_generated_common_proof_pending_statement(
        generated_proof_handle,
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(source.roster_position()),
        Some(source.batch_schedule_position()),
        source.canonical_application_statement_bytes(),
    )?;
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_collecting()?;
        let roster_position = source.roster_position();
        let expected_participant_identity = assembly
            .expected_ordered_participant_identities
            .get(usize::from(roster_position))
            .copied()
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
        let [expected_batch_schedule_position] = selected_galois_key_share_batch_schedule();
        let expected_galois_positions = selected_evaluator_galois_entry_positions()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if assembly
            .generated_galois_sources
            .contains_key(&roster_position)
            || assembly.pending_galois_proofs.contains_key(&roster_position)
            || source.protocol_version() != assembly.expected_protocol_version
            || source.suite_identifier() != assembly.expected_suite_identifier
            || source.ceremony_context_hash() != assembly.expected_ceremony_context_hash
            || source.action_context_hash() != assembly.expected_action_context_hash
            || source.roster_hash() != assembly.expected_roster_hash
            || source.setup_proof_context_hash() != assembly.expected_setup_proof_context_hash
            || source.participant_identity() != expected_participant_identity
            || source.batch_schedule_position() != expected_batch_schedule_position
            || source.ordered_components().len() != expected_galois_positions.len()
            || source
                .ordered_components()
                .iter()
                .zip(&expected_galois_positions)
                .any(|(component, expected_position)| {
                    component.evaluator_position() != *expected_position
                })
            || assembly
                .relinearization_sources
                .get(&roster_position)
                .is_some_and(|relinearization| {
                    relinearization.anchor_commitment_roots()
                        != source.anchor_commitment_roots()
                })
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(PreparedPrepackageGeneratedGaloisSourceSlot {
            assembly_handle,
            roster_position,
            pending_proof: PendingGeneratedCommonProof {
                generated_proof_handle: Some(generated_proof_handle),
                stream_descriptor,
            },
        })
    })
}

pub(crate) fn commit_prepackage_generated_galois_source(
    prepared_slot: PreparedPrepackageGeneratedGaloisSourceSlot,
    source: SetupGeneratedGaloisSourceAuthority,
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
                .pending_galois_proofs
                .insert(prepared_slot.roster_position, prepared_slot.pending_proof)
                .is_none()
        );
        assert!(
            assembly
                .generated_galois_sources
                .insert(prepared_slot.roster_position, source)
                .is_none()
        );
    });
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn preflight_prepackage_generated_evaluator_proof_slot(
    assembly_handle: u32,
    generated_proof_handle: u32,
    evaluator_store_descriptor: &StreamDescriptor,
    canonical_application_statement_bytes: &[u8],
    ordered_runtime_roots: &[VerifiedEvaluatorRuntimeRoot],
    ordered_auxiliary_roots: &[VerifiedEvaluatorAuxiliaryRoot],
) -> Result<PreparedPrepackageGeneratedEvaluatorProofSlot, CommonProofRuntimeError> {
    let proof_stream_descriptor = preflight_generated_common_proof_pending_statement(
        generated_proof_handle,
        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
        None,
        None,
        canonical_application_statement_bytes,
    )?;
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_generation_sources_complete()?;
        if assembly.pending_evaluator_proof.is_some()
            || assembly.package_bound_evaluator_statement_source.is_some()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let top_count = FOUNDATION_PROFILE.option_count;
        let positions = selected_evaluator_entry_positions(top_count)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let statement = decode_selected_application_statement(
            canonical_application_statement_bytes,
            ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
            crate::bgv::proof_suite::SelectedApplicationStatementContext::new(
                assembly.expected_protocol_version,
                assembly.expected_suite_identifier,
                None,
                Some(top_count),
            ),
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let entries = selected_evaluator_aggregate_entry_roots_in_order(&statement, top_count)
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if entries.len() != positions.len()
            || ordered_runtime_roots.len() != positions.len()
            || ordered_auxiliary_roots.len() != positions.len()
            || !statement.items.first().is_some_and(|item| {
                item.item_type() == CanonicalItemType::Hash512
                    && item.canonical_bytes() == assembly.expected_setup_proof_context_hash
            })
            || !statement.items.get(2).is_some_and(|item| {
                item.item_type() == CanonicalItemType::Hash512
                    && item.canonical_bytes()
                        == evaluator_store_descriptor.full_object_digest.as_bytes()
            })
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        for (entry_ordinal, (((entry, position), runtime_root), auxiliary_root)) in entries
            .iter()
            .zip(&positions)
            .zip(ordered_runtime_roots)
            .zip(ordered_auxiliary_roots)
            .enumerate()
        {
            if usize::try_from(entry.entry_ordinal()).ok() != Some(entry_ordinal)
                || entry.position() != *position
                || runtime_root.position() != *position
                || auxiliary_root.position() != *position
                || entry.runtime_component_root() != runtime_root.runtime_component_root()
                || entry.auxiliary_component_root()
                    != auxiliary_root.auxiliary_component_root()
                || entry.source_component_roots().len()
                    != usize::from(FOUNDATION_PROFILE.participant_count)
                || entry
                    .source_component_roots()
                    .iter()
                    .enumerate()
                    .any(|(roster_ordinal, root)| {
                        u16::try_from(roster_ordinal)
                            .ok()
                            .and_then(|roster_position| {
                                assembly.component_root(roster_position, *position)
                            })
                            .as_ref()
                            != Some(root)
                    })
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
        }
        Ok(PreparedPrepackageGeneratedEvaluatorProofSlot {
            assembly_handle,
            pending_proof: PendingGeneratedEvaluatorCommonProof {
                generated_proof_handle: Some(generated_proof_handle),
                stream_descriptor: proof_stream_descriptor,
                canonical_application_statement_bytes: canonical_application_statement_bytes
                    .to_vec()
                    .into_boxed_slice(),
            },
        })
    })
}

pub(crate) fn commit_prepackage_generated_evaluator_proof(
    prepared_slot: PreparedPrepackageGeneratedEvaluatorProofSlot,
) {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared_slot.assembly_handle)
            .expect("preflight retained the exact prepackage source assembly");
        assert!(
            assembly
                .pending_evaluator_proof
                .replace(prepared_slot.pending_proof)
                .is_none()
        );
    });
}

#[allow(clippy::too_many_arguments)]
fn accepted_package_statement_source(
    package: &CanonicalAcceptedSetupPackage,
    verified_public_randomness: &VerifiedPublicRandomness,
    schema_identifier: u16,
    roster_position: Option<u16>,
    schedule_position: Option<u32>,
    top_count: Option<u16>,
    canonical_application_statement_bytes: &[u8],
) -> Result<VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
    let selected_slots = package
        .selected_public_proof_slots()
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let mut matching_indices = selected_slots
        .iter()
        .enumerate()
        .filter(|(_, slot)| {
            slot.application_statement_schema_identifier() == schema_identifier
                && slot.roster_position() == roster_position
                && slot.schedule_position() == schedule_position
        })
        .map(|(index, _)| index);
    let proof_descriptor_index = matching_indices
        .next()
        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
    if matching_indices.next().is_some() {
        return Err(CommonProofRuntimeError::WrongVerificationBinding);
    }
    let proof_stream_descriptor = package
        .ordered_proof_descriptors()
        .get(proof_descriptor_index)
        .cloned()
        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
    let context = verified_public_randomness.context();
    let application_slot = ProofApplicationSlot::new(
        context.suite_identifier(),
        context.ceremony_context_hash(),
        context.action_context_hash(),
        schema_identifier,
        roster_position,
        schedule_position,
        None,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let proof_header = ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.to_vec(),
        &CanonicalDecodeLimits::default(),
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let proof_application_binding = ProofApplicationBinding::new(
        application_slot,
        proof_header
            .proof_header_hash()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?,
        proof_stream_descriptor,
    )
    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
    let relation_plan_artifact = selected_relation_plans()
        .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?
        .into_iter()
        .find(|artifact| artifact.application_statement_schema_identifier() == schema_identifier)
        .ok_or(CommonProofRuntimeError::InvalidPlanCapability)?;
    let relation_plan = relation_plan_artifact.compiled_plan();
    let relation_variant = relation_plan
        .select_variant(schedule_position, top_count)
        .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
    let runtime_limits = selected_proof_runtime_limits(
        schema_identifier,
        canonical_application_statement_bytes,
        relation_variant,
    )
    .map_err(|_| CommonProofRuntimeError::InvalidLimits)?;
    let relation_context = selected_relation_plan_check_context(schema_identifier)
        .ok_or(CommonProofRuntimeError::InvalidPlanCapability)?;
    let relation_plan_capability = CommonProofRelationPlanCapability::from_compiled_plan(
        relation_plan,
        &relation_context,
        schedule_position,
        top_count,
    )
    .map_err(|_| CommonProofRuntimeError::InvalidPlanCapability)?;
    VerifiedCommonProofStatementSource::from_exact_family_verified_accepted_setup_package(
        package,
        verified_public_randomness,
        proof_descriptor_index,
        canonical_application_statement_bytes.to_vec(),
        proof_application_binding,
        relation_plan_capability,
        runtime_limits,
    )
}

fn prepare_prepackage_generated_proof_package_binding(
    accepted_setup_assembly_handle: u32,
    prepackage_assembly_handle: u32,
) -> Result<PreparedPrepackageGeneratedProofPackageBinding, CommonProofRuntimeError> {
    with_accepted_setup_verification_sources(
        accepted_setup_assembly_handle,
        |package, verified_public_randomness| {
            PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
                let registry = registry.borrow();
                let assembly = registry.get(prepackage_assembly_handle)?;
                assembly.require_generation_sources_complete()?;
                if !assembly.package_bound_galois_statement_sources.is_empty()
                    || assembly.package_bound_evaluator_statement_source.is_some()
                {
                    return Err(CommonProofRuntimeError::WrongOperationPhase);
                }
                let evaluator_proof = assembly
                    .pending_evaluator_proof
                    .as_ref()
                    .filter(|proof| proof.generated_proof_handle.is_some())
                    .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
                let [galois_batch_schedule_position] =
                    selected_galois_key_share_batch_schedule();
                let mut ordered_sources = Vec::new();
                ordered_sources
                    .try_reserve_exact(
                        usize::from(FOUNDATION_PROFILE.participant_count) + 1,
                    )
                    .map_err(|_| CommonProofRuntimeError::AllocationLimitExceeded)?;
                for roster_position in 0..FOUNDATION_PROFILE.participant_count {
                    let generated_source = assembly
                        .generated_galois_sources
                        .get(&roster_position)
                        .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
                    let pending_proof = assembly
                        .pending_galois_proofs
                        .get(&roster_position)
                        .filter(|proof| proof.generated_proof_handle.is_some())
                        .ok_or(CommonProofRuntimeError::WrongOperationPhase)?;
                    let statement_source = accepted_package_statement_source(
                        package,
                        verified_public_randomness,
                        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
                        Some(roster_position),
                        Some(galois_batch_schedule_position),
                        None,
                        generated_source.canonical_application_statement_bytes(),
                    )?;
                    ordered_sources.push(PreparedPackageBoundStatementSource {
                        roster_position: Some(roster_position),
                        generated_proof_handle: pending_proof
                            .generated_proof_handle
                            .expect("the filtered pending Galois proof has a live handle"),
                        statement_source,
                    });
                }
                ordered_sources.push(PreparedPackageBoundStatementSource {
                    roster_position: None,
                    generated_proof_handle: evaluator_proof
                        .generated_proof_handle
                        .expect("the filtered pending evaluator proof has a live handle"),
                    statement_source: accepted_package_statement_source(
                        package,
                        verified_public_randomness,
                        ProofApplicationSlotCeilings::EVALUATOR_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                        None,
                        None,
                        Some(FOUNDATION_PROFILE.option_count),
                        &evaluator_proof.canonical_application_statement_bytes,
                    )?,
                });
                Ok(PreparedPrepackageGeneratedProofPackageBinding {
                    prepackage_assembly_handle,
                    ordered_sources,
                })
            })
        },
    )
}

pub(crate) fn bind_prepackage_generated_proofs_to_accepted_setup_package(
    accepted_setup_assembly_handle: u32,
    prepackage_assembly_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let prepared = prepare_prepackage_generated_proof_package_binding(
        accepted_setup_assembly_handle,
        prepackage_assembly_handle,
    )?;
    let bindings = prepared
        .ordered_sources
        .iter()
        .map(|source| (source.generated_proof_handle, &source.statement_source))
        .collect::<Vec<_>>();
    bind_generated_common_proofs_to_verified_statement_sources(&bindings)?;
    drop(bindings);
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry
            .assemblies
            .get_mut(&prepared.prepackage_assembly_handle)
            .expect("package-binding preflight retained the prepackage source assembly");
        for prepared_source in prepared.ordered_sources {
            match prepared_source.roster_position {
                Some(roster_position) => {
                    let pending_proof = assembly
                        .pending_galois_proofs
                        .get_mut(&roster_position)
                        .expect("package-binding preflight retained the pending Galois proof");
                    assert_eq!(
                        pending_proof.generated_proof_handle.take(),
                        Some(prepared_source.generated_proof_handle)
                    );
                    assert!(
                        assembly
                            .package_bound_galois_statement_sources
                            .insert(roster_position, prepared_source.statement_source)
                            .is_none()
                    );
                }
                None => {
                    let pending_proof = assembly
                        .pending_evaluator_proof
                        .as_mut()
                        .expect("package-binding preflight retained the pending evaluator proof");
                    assert_eq!(
                        pending_proof.generated_proof_handle.take(),
                        Some(prepared_source.generated_proof_handle)
                    );
                    assert!(
                        assembly
                            .package_bound_evaluator_statement_source
                            .replace(prepared_source.statement_source)
                            .is_none()
                    );
                }
            }
        }
    });
    Ok(())
}

pub(crate) fn take_prepackage_galois_statement_source(
    assembly_handle: u32,
    roster_position: u16,
) -> Result<VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry.get_mut(assembly_handle)?;
        if assembly
            .pending_galois_proofs
            .get(&roster_position)
            .is_none_or(|proof| proof.generated_proof_handle.is_some())
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        assembly
            .package_bound_galois_statement_sources
            .remove(&roster_position)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    })
}

pub(crate) fn restore_prepackage_galois_statement_source(
    assembly_handle: u32,
    roster_position: u16,
    statement_source: VerifiedCommonProofStatementSource,
) -> Result<(), CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry.get_mut(assembly_handle)?;
        if assembly
            .pending_galois_proofs
            .get(&roster_position)
            .is_none_or(|proof| proof.generated_proof_handle.is_some())
            || assembly
                .package_bound_galois_statement_sources
                .contains_key(&roster_position)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        assert!(
            assembly
                .package_bound_galois_statement_sources
                .insert(roster_position, statement_source)
                .is_none()
        );
        Ok(())
    })
}

pub(crate) fn take_prepackage_evaluator_statement_source(
    assembly_handle: u32,
) -> Result<VerifiedCommonProofStatementSource, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry.get_mut(assembly_handle)?;
        if assembly
            .pending_evaluator_proof
            .as_ref()
            .is_none_or(|proof| proof.generated_proof_handle.is_some())
        {
            return Err(CommonProofRuntimeError::WrongOperationPhase);
        }
        assembly
            .package_bound_evaluator_statement_source
            .take()
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    })
}

pub(crate) fn restore_prepackage_evaluator_statement_source(
    assembly_handle: u32,
    statement_source: VerifiedCommonProofStatementSource,
) -> Result<(), CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let assembly = registry.get_mut(assembly_handle)?;
        if assembly
            .pending_evaluator_proof
            .as_ref()
            .is_none_or(|proof| proof.generated_proof_handle.is_some())
            || assembly.package_bound_evaluator_statement_source.is_some()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        assert!(
            assembly
                .package_bound_evaluator_statement_source
                .replace(statement_source)
                .is_none()
        );
        Ok(())
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

pub(crate) fn with_prepackage_evaluator_generation_sources<Output>(
    assembly_handle: u32,
    inspect: impl FnOnce(
        &dyn SelectedEvaluatorStoreSourceCatalog,
        &VerifiedRelinearizationAggregateMaterial,
        &[VerifiedEvaluatorAuxiliaryRoot],
    ) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let assembly = registry.get(assembly_handle)?;
        assembly.require_generation_sources_complete()?;
        let ordered_auxiliary_roots = assembly.ordered_generation_auxiliary_roots()?;
        inspect(
            assembly,
            assembly
                .relinearization_aggregate
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongOperationPhase)?,
            &ordered_auxiliary_roots,
        )
    })
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
    let assembly = PREPACKAGE_EVALUATOR_SOURCE_CATALOG_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .assemblies
            .remove(&assembly_handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    })?;
    let mut generated_proof_handles = assembly
        .pending_galois_proofs
        .values()
        .filter_map(|proof| proof.generated_proof_handle)
        .collect::<Vec<_>>();
    if let Some(generated_proof_handle) = assembly
        .pending_evaluator_proof
        .as_ref()
        .and_then(|proof| proof.generated_proof_handle)
    {
        generated_proof_handles.push(generated_proof_handle);
    }
    let retirement_result =
        retire_generated_common_proof_capabilities(&generated_proof_handles);
    drop(assembly);
    retirement_result
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

/// Binds the ten generated Galois proofs and the single complete-list
/// evaluator proof to their exact canonical accepted-package slots in one
/// transition. No generated capability is consumed when any descriptor or
/// statement coordinate differs.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_prepackage_evaluator_generated_proofs_bind_package(
    accepted_setup_assembly_handle: u32,
    prepackage_assembly_handle: u32,
) -> u32 {
    bind_prepackage_generated_proofs_to_accepted_setup_package(
        accepted_setup_assembly_handle,
        prepackage_assembly_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_prepackage_evaluator_source_catalog_cancel(
    assembly_handle: u32,
) -> u32 {
    cancel_prepackage_evaluator_source_catalog(assembly_handle)
        .map_or_else(runtime_error_status, |()| 0)
}
