//! Reset-safe terminal population for collective-public-key and selected
//! relinearization proof families.
//!
//! Source preparation is intentionally internal. A caller cannot manufacture
//! a terminal source from roots or descriptors; a production statement-source
//! authority must retain the recomputed trees, authenticated materials, and
//! statement-owned tree catalog together before exposing an adapter.

use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    bgv::proof_suite::{
        CommonProofRuntimeError, SetupPublicPolynomialTree, VerifiedCommonProofCapabilityHandle,
        VerifiedKeySwitchComponentMaterial, VerifiedRelinearizationAggregateMaterial,
        VerifiedRelinearizationRoundOneSourceMaterial,
        VerifiedRelinearizationRoundOneSourceMaterialPreflight,
        VerifiedRelinearizationSourceMaterial, VerifiedStatementOwnedTree,
        bind_generated_common_proof_to_verified_statement_source,
        preflight_and_consume_verified_common_proof_with_family_terminal,
        preflight_generated_common_proof_pending_statement, runtime_error_status,
    },
    foundation::Hash512,
};

use super::{
    prepackage_evaluator_source_catalog::{
        commit_prepackage_relinearization_aggregate,
        commit_prepackage_relinearization_round_one_source,
        commit_prepackage_relinearization_source,
        consume_prepackage_relinearization_round_one_sources,
        preflight_prepackage_relinearization_aggregate_slot,
        preflight_prepackage_relinearization_round_one_source_slot,
        preflight_prepackage_relinearization_source_slot,
        with_prepackage_relinearization_round_one_sources,
    },
    verification_assembly::{
        commit_preflighted_verified_collective_public_key_terminal,
        preflight_verified_collective_public_key_terminal_slot, with_verified_same_secret_terminal,
    },
    verified_terminals::VerifiedCollectivePublicKeyTerminal,
};

const MAXIMUM_RETAINED_TERMINAL_SOURCES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VerificationTerminalFamily {
    CollectivePublicKey,
    RelinearizationRoundOne,
    RelinearizationRoundOneAggregate,
    RelinearizationRoundTwo,
}

struct CollectivePublicKeyTerminalSource {
    verification_assembly_handle: u32,
    canonical_application_statement_bytes: Box<[u8]>,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_trees: Box<[VerifiedStatementOwnedTree]>,
    collective_public_key_tree: SetupPublicPolynomialTree,
}

struct RelinearizationRoundOneTerminalSource {
    verification_assembly_handle: u32,
    prepackage_catalog_handle: u32,
    canonical_application_statement_bytes: Box<[u8]>,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_trees: Box<[VerifiedStatementOwnedTree]>,
    component_trees: [SetupPublicPolynomialTree; 2],
    component_materials: [VerifiedKeySwitchComponentMaterial; 2],
}

struct RelinearizationRoundOneAggregateTerminalSource {
    prepackage_catalog_handle: u32,
    canonical_application_statement_bytes: Box<[u8]>,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_trees: Box<[VerifiedStatementOwnedTree]>,
    aggregate_trees: [SetupPublicPolynomialTree; 2],
    aggregate_materials: [VerifiedKeySwitchComponentMaterial; 2],
}

struct RelinearizationRoundTwoTerminalSource {
    prepackage_catalog_handle: u32,
    canonical_application_statement_bytes: Box<[u8]>,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_trees: Box<[VerifiedStatementOwnedTree]>,
    contribution_tree: SetupPublicPolynomialTree,
    material: VerifiedKeySwitchComponentMaterial,
}

enum VerificationTerminalSource {
    CollectivePublicKey(CollectivePublicKeyTerminalSource),
    RelinearizationRoundOne(RelinearizationRoundOneTerminalSource),
    RelinearizationRoundOneAggregate(RelinearizationRoundOneAggregateTerminalSource),
    RelinearizationRoundTwo(RelinearizationRoundTwoTerminalSource),
}

impl VerificationTerminalSource {
    const fn family(&self) -> VerificationTerminalFamily {
        match self {
            Self::CollectivePublicKey(_) => VerificationTerminalFamily::CollectivePublicKey,
            Self::RelinearizationRoundOne(_) => VerificationTerminalFamily::RelinearizationRoundOne,
            Self::RelinearizationRoundOneAggregate(_) => {
                VerificationTerminalFamily::RelinearizationRoundOneAggregate
            }
            Self::RelinearizationRoundTwo(_) => VerificationTerminalFamily::RelinearizationRoundTwo,
        }
    }
}

struct VerificationTerminalSourceRegistry {
    next_handle: u32,
    sources: BTreeMap<u32, VerificationTerminalSource>,
    reservations: BTreeMap<u32, VerificationTerminalFamily>,
}

impl Default for VerificationTerminalSourceRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            sources: BTreeMap::new(),
            reservations: BTreeMap::new(),
        }
    }
}

impl VerificationTerminalSourceRegistry {
    fn retain(
        &mut self,
        source: VerificationTerminalSource,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self
            .sources
            .len()
            .checked_add(self.reservations.len())
            .is_none_or(|count| count >= MAXIMUM_RETAINED_TERMINAL_SOURCES)
            || self.next_handle == 0
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next_handle| *next_handle != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if self.sources.insert(handle, source).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(handle)
    }

    fn reserve(
        &mut self,
        family: VerificationTerminalFamily,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self
            .sources
            .len()
            .checked_add(self.reservations.len())
            .is_none_or(|count| count >= MAXIMUM_RETAINED_TERMINAL_SOURCES)
            || self.next_handle == 0
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next_handle| *next_handle != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if self.reservations.insert(handle, family).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(handle)
    }

    fn commit_reservation(
        &mut self,
        handle: u32,
        source: VerificationTerminalSource,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.reservations.get(&handle).copied() != Some(source.family())
            || self.sources.contains_key(&handle)
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.reservations.remove(&handle);
        if self.sources.insert(handle, source).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(())
    }

    fn cancel_reservation(
        &mut self,
        handle: u32,
        family: VerificationTerminalFamily,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.reservations.get(&handle).copied() != Some(family) {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.reservations.remove(&handle);
        Ok(())
    }

    fn take(
        &mut self,
        handle: u32,
        expected_family: VerificationTerminalFamily,
    ) -> Result<VerificationTerminalSource, CommonProofRuntimeError> {
        let source = self
            .sources
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        if source.family() != expected_family {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.sources
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }

    fn restore(
        &mut self,
        handle: u32,
        source: VerificationTerminalSource,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.sources.insert(handle, source).is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(())
    }
}

pub(crate) fn reserve_collective_public_key_verification_terminal_source()
-> Result<u32, CommonProofRuntimeError> {
    VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .reserve(VerificationTerminalFamily::CollectivePublicKey)
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn commit_reserved_collective_public_key_verification_terminal_source(
    reservation_handle: u32,
    verification_assembly_handle: u32,
    canonical_application_statement_bytes: Vec<u8>,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_trees: Vec<VerifiedStatementOwnedTree>,
    collective_public_key_tree: SetupPublicPolynomialTree,
) {
    VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .commit_reservation(
                reservation_handle,
                VerificationTerminalSource::CollectivePublicKey(
                    CollectivePublicKeyTerminalSource {
                        verification_assembly_handle,
                        canonical_application_statement_bytes:
                            canonical_application_statement_bytes.into_boxed_slice(),
                        roster_hash,
                        statement_trees: statement_trees.into_boxed_slice(),
                        collective_public_key_tree,
                    },
                ),
            )
            .expect("a collective terminal reservation commits its exact preflighted source");
    });
}

pub(crate) fn cancel_collective_public_key_verification_terminal_source_reservation(
    reservation_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry.borrow_mut().cancel_reservation(
            reservation_handle,
            VerificationTerminalFamily::CollectivePublicKey,
        )
    })
}

thread_local! {
    static VERIFICATION_TERMINAL_SOURCE_REGISTRY:
        RefCell<VerificationTerminalSourceRegistry> =
            RefCell::new(VerificationTerminalSourceRegistry::default());
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn retain_relinearization_round_one_verification_terminal_source(
    verification_assembly_handle: u32,
    prepackage_catalog_handle: u32,
    canonical_application_statement_bytes: Vec<u8>,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_trees: Vec<VerifiedStatementOwnedTree>,
    component_trees: [SetupPublicPolynomialTree; 2],
    component_materials: [VerifiedKeySwitchComponentMaterial; 2],
) -> Result<u32, CommonProofRuntimeError> {
    VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .retain(VerificationTerminalSource::RelinearizationRoundOne(
                RelinearizationRoundOneTerminalSource {
                    verification_assembly_handle,
                    prepackage_catalog_handle,
                    canonical_application_statement_bytes: canonical_application_statement_bytes
                        .into_boxed_slice(),
                    roster_hash,
                    statement_trees: statement_trees.into_boxed_slice(),
                    component_trees,
                    component_materials,
                },
            ))
    })
}

pub(crate) fn retain_relinearization_round_one_aggregate_verification_terminal_source(
    prepackage_catalog_handle: u32,
    canonical_application_statement_bytes: Vec<u8>,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_trees: Vec<VerifiedStatementOwnedTree>,
    aggregate_trees: [SetupPublicPolynomialTree; 2],
    aggregate_materials: [VerifiedKeySwitchComponentMaterial; 2],
) -> Result<u32, CommonProofRuntimeError> {
    VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry.borrow_mut().retain(
            VerificationTerminalSource::RelinearizationRoundOneAggregate(
                RelinearizationRoundOneAggregateTerminalSource {
                    prepackage_catalog_handle,
                    canonical_application_statement_bytes: canonical_application_statement_bytes
                        .into_boxed_slice(),
                    roster_hash,
                    statement_trees: statement_trees.into_boxed_slice(),
                    aggregate_trees,
                    aggregate_materials,
                },
            ),
        )
    })
}

pub(crate) fn retain_relinearization_round_two_verification_terminal_source(
    prepackage_catalog_handle: u32,
    canonical_application_statement_bytes: Vec<u8>,
    roster_hash: [u8; Hash512::BYTE_LENGTH],
    statement_trees: Vec<VerifiedStatementOwnedTree>,
    contribution_tree: SetupPublicPolynomialTree,
    material: VerifiedKeySwitchComponentMaterial,
) -> Result<u32, CommonProofRuntimeError> {
    VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .retain(VerificationTerminalSource::RelinearizationRoundTwo(
                RelinearizationRoundTwoTerminalSource {
                    prepackage_catalog_handle,
                    canonical_application_statement_bytes: canonical_application_statement_bytes
                        .into_boxed_slice(),
                    roster_hash,
                    statement_trees: statement_trees.into_boxed_slice(),
                    contribution_tree,
                    material,
                },
            ))
    })
}

fn restore_terminal_source(
    terminal_source_handle: u32,
    terminal_source: VerificationTerminalSource,
) -> Result<(), CommonProofRuntimeError> {
    VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .restore(terminal_source_handle, terminal_source)
    })
}

fn finish_collective_public_key_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    generated_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source = VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry.borrow_mut().take(
            terminal_source_handle,
            VerificationTerminalFamily::CollectivePublicKey,
        )
    })?;
    let VerificationTerminalSource::CollectivePublicKey(terminal_source) = terminal_source else {
        unreachable!("family-checked terminal source variant")
    };
    let terminal_source = RefCell::new(Some(terminal_source));
    let generated_proof_descriptor = {
        let preliminary_result = (|| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            preflight_generated_common_proof_pending_statement(
                generated_common_proof_handle,
                crate::foundation::ProofApplicationSlotCeilings::COLLECTIVE_PUBLIC_KEY_AGGREGATE_STATEMENT_SCHEMA_IDENTIFIER,
                None,
                None,
                &source.canonical_application_statement_bytes,
            )
        })();
        match preliminary_result {
            Ok(descriptor) => descriptor,
            Err(error) => {
                let source = terminal_source
                    .into_inner()
                    .expect("generated-proof preflight retained the collective terminal source");
                restore_terminal_source(
                    terminal_source_handle,
                    VerificationTerminalSource::CollectivePublicKey(source),
                )?;
                return Err(error);
            }
        }
    };
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_proof| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            if verified_proof.proof_stream_descriptor() != &generated_proof_descriptor {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            let terminal_preflight =
                VerifiedCollectivePublicKeyTerminal::preflight_from_borrowed_common_proof_and_tree(
                    verified_proof,
                    &source.canonical_application_statement_bytes,
                    source.roster_hash,
                    &source.statement_trees,
                    &source.collective_public_key_tree,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let prepared_slot = preflight_verified_collective_public_key_terminal_slot(
                source.verification_assembly_handle,
                &terminal_preflight,
            )?;
            Ok((terminal_preflight, prepared_slot))
        },
        |verified_proof, (terminal_preflight, prepared_slot)| {
            bind_generated_common_proof_to_verified_statement_source(
                generated_common_proof_handle,
                verified_proof
                    .statement_source()
                    .expect("collective preflight retained its package statement source"),
            )
            .expect("collective preflight established the generated package binding");
            let source = terminal_source
                .borrow_mut()
                .take()
                .expect("collective-key preflight retained the exact terminal source");
            let terminal =
                terminal_preflight.complete(verified_proof, source.collective_public_key_tree);
            commit_preflighted_verified_collective_public_key_terminal(prepared_slot, terminal);
        },
    );
    if result.is_err()
        && let Some(source) = terminal_source.into_inner()
    {
        restore_terminal_source(
            terminal_source_handle,
            VerificationTerminalSource::CollectivePublicKey(source),
        )?;
    }
    result
}

fn round_one_source_matches_same_secret_terminal(
    verification_assembly_handle: u32,
    source: &VerifiedRelinearizationRoundOneSourceMaterialPreflight,
) -> Result<(), CommonProofRuntimeError> {
    with_verified_same_secret_terminal(
        verification_assembly_handle,
        source.roster_position(),
        |same_secret| {
            if source.protocol_version() != same_secret.protocol_version()
                || source.suite_identifier() != same_secret.suite_identifier()
                || source.ceremony_context_hash() != same_secret.ceremony_context_hash()
                || source.action_context_hash() != same_secret.action_context_hash()
                || source.roster_hash() != same_secret.roster_hash()
                || source.setup_proof_context_hash() != same_secret.setup_proof_context_hash()
                || source.participant_identity() != same_secret.participant_identity()
                || source.anchor_commitment_roots() != same_secret.anchor_commitment_roots()
            {
                return Err(CommonProofRuntimeError::WrongVerificationBinding);
            }
            Ok(())
        },
    )
}

fn finish_relinearization_round_one_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source = VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry.borrow_mut().take(
            terminal_source_handle,
            VerificationTerminalFamily::RelinearizationRoundOne,
        )
    })?;
    let VerificationTerminalSource::RelinearizationRoundOne(terminal_source) = terminal_source
    else {
        unreachable!("family-checked terminal source variant")
    };
    let terminal_source = RefCell::new(Some(terminal_source));
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_proof| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight =
                VerifiedRelinearizationRoundOneSourceMaterial::preflight_from_borrowed_common_proof(
                    verified_proof,
                    &source.canonical_application_statement_bytes,
                    source.roster_hash,
                    &source.statement_trees,
                    &source.component_trees,
                    &source.component_materials,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            round_one_source_matches_same_secret_terminal(
                source.verification_assembly_handle,
                &terminal_preflight,
            )?;
            let prepared_slot = preflight_prepackage_relinearization_round_one_source_slot(
                source.prepackage_catalog_handle,
                &terminal_preflight,
            )?;
            Ok((terminal_preflight, prepared_slot))
        },
        |verified_proof, (terminal_preflight, prepared_slot)| {
            let source = terminal_source
                .borrow_mut()
                .take()
                .expect("round-one preflight retained the exact terminal source");
            let terminal = terminal_preflight.complete(
                verified_proof,
                source.component_trees,
                source.component_materials,
            );
            commit_prepackage_relinearization_round_one_source(prepared_slot, terminal);
        },
    );
    if result.is_err()
        && let Some(source) = terminal_source.into_inner()
    {
        restore_terminal_source(
            terminal_source_handle,
            VerificationTerminalSource::RelinearizationRoundOne(source),
        )?;
    }
    result
}

fn finish_relinearization_round_one_aggregate_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source = VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry.borrow_mut().take(
            terminal_source_handle,
            VerificationTerminalFamily::RelinearizationRoundOneAggregate,
        )
    })?;
    let VerificationTerminalSource::RelinearizationRoundOneAggregate(terminal_source) =
        terminal_source
    else {
        unreachable!("family-checked terminal source variant")
    };
    let terminal_source = RefCell::new(Some(terminal_source));
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_proof| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight = with_prepackage_relinearization_round_one_sources(
                source.prepackage_catalog_handle,
                |ordered_sources| {
                    VerifiedRelinearizationAggregateMaterial::preflight_from_borrowed_common_proof(
                        verified_proof,
                        &source.canonical_application_statement_bytes,
                        source.roster_hash,
                        &source.statement_trees,
                        ordered_sources,
                        &source.aggregate_trees[0],
                        &source.aggregate_materials[0],
                        &source.aggregate_trees[1],
                        &source.aggregate_materials[1],
                    )
                    .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
                },
            )?;
            let prepared_slot = preflight_prepackage_relinearization_aggregate_slot(
                source.prepackage_catalog_handle,
                &terminal_preflight,
            )?;
            Ok((terminal_preflight, prepared_slot))
        },
        |verified_proof, (terminal_preflight, prepared_slot)| {
            let source = terminal_source
                .borrow_mut()
                .take()
                .expect("round-one aggregate preflight retained the exact terminal source");
            let (prepared_slot, ordered_sources) =
                consume_prepackage_relinearization_round_one_sources(prepared_slot);
            let [aggregate_left_tree, aggregate_right_tree] = source.aggregate_trees;
            let [aggregate_left_material, aggregate_right_material] = source.aggregate_materials;
            let aggregate = terminal_preflight.complete(
                verified_proof,
                ordered_sources,
                aggregate_left_tree,
                aggregate_left_material,
                aggregate_right_tree,
                aggregate_right_material,
            );
            commit_prepackage_relinearization_aggregate(prepared_slot, aggregate);
        },
    );
    if result.is_err()
        && let Some(source) = terminal_source.into_inner()
    {
        restore_terminal_source(
            terminal_source_handle,
            VerificationTerminalSource::RelinearizationRoundOneAggregate(source),
        )?;
    }
    result
}

fn finish_relinearization_round_two_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let terminal_source = VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry.borrow_mut().take(
            terminal_source_handle,
            VerificationTerminalFamily::RelinearizationRoundTwo,
        )
    })?;
    let VerificationTerminalSource::RelinearizationRoundTwo(terminal_source) = terminal_source
    else {
        unreachable!("family-checked terminal source variant")
    };
    let terminal_source = RefCell::new(Some(terminal_source));
    let result = preflight_and_consume_verified_common_proof_with_family_terminal(
        &VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_proof| {
            let source = terminal_source.borrow();
            let source = source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let terminal_preflight =
                VerifiedRelinearizationSourceMaterial::preflight_from_borrowed_common_proof(
                    verified_proof,
                    &source.canonical_application_statement_bytes,
                    source.roster_hash,
                    &source.statement_trees,
                    &source.contribution_tree,
                    &source.material,
                )
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let prepared_slot = preflight_prepackage_relinearization_source_slot(
                source.prepackage_catalog_handle,
                &terminal_preflight,
            )?;
            Ok((terminal_preflight, prepared_slot))
        },
        |verified_proof, (terminal_preflight, prepared_slot)| {
            let source = terminal_source
                .borrow_mut()
                .take()
                .expect("round-two preflight retained the exact terminal source");
            let terminal = terminal_preflight.complete(
                verified_proof,
                source.contribution_tree,
                source.material,
            );
            commit_prepackage_relinearization_source(prepared_slot, terminal);
        },
    );
    if result.is_err()
        && let Some(source) = terminal_source.into_inner()
    {
        restore_terminal_source(
            terminal_source_handle,
            VerificationTerminalSource::RelinearizationRoundTwo(source),
        )?;
    }
    result
}

fn discard_verification_terminal_source(
    terminal_source_handle: u32,
    family: VerificationTerminalFamily,
) -> Result<(), CommonProofRuntimeError> {
    VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(terminal_source_handle, family)
            .map(|_| ())
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_collective_public_key_aggregate_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    generated_common_proof_handle: u32,
) -> u32 {
    finish_collective_public_key_verification(
        verified_common_proof_handle,
        terminal_source_handle,
        generated_common_proof_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_collective_public_key_aggregate_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    discard_verification_terminal_source(
        terminal_source_handle,
        VerificationTerminalFamily::CollectivePublicKey,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_one_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> u32 {
    finish_relinearization_round_one_verification(
        verified_common_proof_handle,
        terminal_source_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_one_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    discard_verification_terminal_source(
        terminal_source_handle,
        VerificationTerminalFamily::RelinearizationRoundOne,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_one_aggregate_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> u32 {
    finish_relinearization_round_one_aggregate_verification(
        verified_common_proof_handle,
        terminal_source_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_one_aggregate_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    discard_verification_terminal_source(
        terminal_source_handle,
        VerificationTerminalFamily::RelinearizationRoundOneAggregate,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_two_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> u32 {
    finish_relinearization_round_two_verification(
        verified_common_proof_handle,
        terminal_source_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_relinearization_round_two_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    discard_verification_terminal_source(
        terminal_source_handle,
        VerificationTerminalFamily::RelinearizationRoundTwo,
    )
    .map_or_else(runtime_error_status, |()| 0)
}
