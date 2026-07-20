use std::{
    collections::{BTreeMap, BTreeSet},
    mem::size_of,
    sync::{Arc, Mutex, MutexGuard, OnceLock},
};

use crate::{
    bgv::{
        key_switch_topology::KeySwitchDecompositionTopology,
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
        proof_suite::{
            AuthenticatedCompactCommittedMaterialSource, CommittedMaterialContext,
            CommittedMaterialRole, CommittedMaterialSharedAllocationMemoryAccounting,
            CompactCommittedMaterialSource, SelectedEvaluatorEntryKind,
            SelectedEvaluatorEntryPosition, VerifiedEvaluatorKeyStore,
            authenticated_committed_material_shared_allocation_byte_lengths,
            selected_committed_material_profile,
        },
        setup::{
            sample_collective_public_key_common_reference_limb, sample_galois_common_reference_limb,
        },
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    foundation::{
        CanonicalItem, CanonicalStreamDomain, CanonicalStreamWriter, FOUNDATION_PROFILE, Hash512,
        RefusalReason, hash_foundation_tuple_512, selected_sharing_data_prime_coordinates,
        selected_target_data_prime_coordinates,
    },
};

use super::{
    generation_authority::SetupGeneratedCommittedMaterial,
    verified_terminals::{
        VerifiedAggregateThresholdShareTerminal, VerifiedCollectivePublicKeyTerminal,
    },
};

const COLLECTIVE_PUBLIC_KEY_COMPONENT_COUNT: usize = 2;
const COLLECTIVE_PUBLIC_KEY_B_COMPONENT_ORDINAL: u16 = 0;
const COLLECTIVE_PUBLIC_KEY_COMMON_REFERENCE_COMPONENT_ORDINAL: u16 = 1;
const EVALUATOR_REPLAY_CONTEXT_HASH_DOMAIN: &str = "sealed-lattice/evaluator/replay-context/v1";
const DATA_MODULUS_CATALOG_IDENTIFIER: u16 = 1;
const SPECIAL_MODULUS_CATALOG_IDENTIFIER: u16 = 2;

/// Process-local reference to one retained accepted setup. The monotonically
/// allocated value is never a protocol field and cannot recreate authority
/// after release.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VerifiedAcceptedSetupAuthorityHandle(u32);

impl VerifiedAcceptedSetupAuthorityHandle {
    /// Reconstructs only the process-local lookup key used by worker commands.
    /// Registry access remains the authority check; an unknown or released
    /// identifier cannot construct accepted setup state.
    pub(crate) const fn from_identifier(identifier: u32) -> Self {
        Self(identifier)
    }

    pub(crate) const fn identifier(&self) -> u32 {
        self.0
    }
}

pub(crate) struct VerifiedAcceptedSetupParticipantReleaseMaterial {
    participant_identity: [u8; 64],
    roster_position: u16,
    ordered_aggregate_threshold_roots: Box<[[u8; 64]]>,
}

impl VerifiedAcceptedSetupParticipantReleaseMaterial {
    pub(crate) const fn participant_identity(&self) -> [u8; 64] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) fn ordered_aggregate_threshold_roots(&self) -> &[[u8; 64]] {
        &self.ordered_aggregate_threshold_roots
    }

    /// Derives the exact public-root sequence consumed by the selected
    /// target-share relation from the complete verifier-accepted sharing
    /// basis. The target-basis coordinates remain the sole ordering authority.
    pub(crate) fn selected_target_aggregate_threshold_roots(
        &self,
    ) -> CanonicalResult<Box<[[u8; 64]]>> {
        let selected_target_coordinates =
            selected_target_data_prime_coordinates().map_err(|_| authority_binding_error())?;
        let selected_sharing_coordinates =
            selected_sharing_data_prime_coordinates().map_err(|_| authority_binding_error())?;
        if selected_target_coordinates != selected_sharing_coordinates
            || self.ordered_aggregate_threshold_roots.len() != selected_sharing_coordinates.len()
        {
            return Err(authority_binding_error());
        }
        Ok(self.ordered_aggregate_threshold_roots.clone())
    }

    pub(super) fn from_verified_aggregate_threshold_share(
        terminal: &VerifiedAggregateThresholdShareTerminal,
    ) -> Self {
        Self {
            participant_identity: terminal.participant_identity(),
            roster_position: terminal.roster_position(),
            ordered_aggregate_threshold_roots: terminal
                .ordered_aggregate_threshold_roots()
                .to_vec()
                .into_boxed_slice(),
        }
    }

    #[cfg(test)]
    fn from_test_values(
        participant_identity: [u8; 64],
        roster_position: u16,
        ordered_aggregate_threshold_roots: Vec<[u8; 64]>,
    ) -> Self {
        Self {
            participant_identity,
            roster_position,
            ordered_aggregate_threshold_roots: ordered_aggregate_threshold_roots.into_boxed_slice(),
        }
    }
}

/// One browser-owned target-release opening. Construction remains inside the
/// accepted-setup module so transport bytes cannot create it; the terminal
/// join below positively matches both the root and the masked tree opening.
pub(in crate::bgv) struct BrowserOwnedAggregateThresholdShareLimb {
    data_modulus_index: u16,
    committed_share: SetupGeneratedCommittedMaterial,
}

impl BrowserOwnedAggregateThresholdShareLimb {
    pub(in crate::bgv) fn from_proof_generation_source(
        data_modulus_index: u16,
        committed_share: SetupGeneratedCommittedMaterial,
    ) -> Self {
        Self {
            data_modulus_index,
            committed_share,
        }
    }

    pub(super) const fn data_modulus_index(&self) -> u16 {
        self.data_modulus_index
    }

    pub(super) fn material_context_hash(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.committed_share
            .compact_source()
            .material_context_hash()
    }
}

pub(crate) struct VerifiedAcceptedSetupParticipantTargetReleaseLimb {
    data_modulus_index: u16,
    modulus: u64,
    committed_share: AuthenticatedCompactCommittedMaterialSource,
}

impl VerifiedAcceptedSetupParticipantTargetReleaseLimb {
    pub(crate) fn threshold_share(&self) -> &[u64] {
        self.committed_share.canonical_message()
    }
}

pub(crate) struct VerifiedAcceptedSetupParticipantTargetReleaseLease {
    participant_identity: [u8; 64],
    roster_position: u16,
    ordered_limbs: Box<[VerifiedAcceptedSetupParticipantTargetReleaseLeaseLimb]>,
}

pub(crate) struct VerifiedAcceptedSetupParticipantTargetReleaseLeaseMemoryAccounting {
    unique_owned_heap_byte_length: u64,
    shared_allocations: Box<[CommittedMaterialSharedAllocationMemoryAccounting]>,
}

fn target_release_lease_unique_owned_heap_byte_length(limb_count: usize) -> CanonicalResult<u64> {
    limb_count
        .checked_mul(size_of::<
            VerifiedAcceptedSetupParticipantTargetReleaseLeaseLimb,
        >())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or_else(authority_binding_error)
}

impl VerifiedAcceptedSetupParticipantTargetReleaseLeaseMemoryAccounting {
    pub(crate) const fn unique_owned_heap_byte_length(&self) -> u64 {
        self.unique_owned_heap_byte_length
    }

    pub(crate) fn shared_allocations(
        &self,
    ) -> &[CommittedMaterialSharedAllocationMemoryAccounting] {
        &self.shared_allocations
    }
}

struct VerifiedAcceptedSetupParticipantTargetReleaseLeaseLimb {
    data_modulus_index: u16,
    modulus: u64,
    committed_share: AuthenticatedCompactCommittedMaterialSource,
}

impl VerifiedAcceptedSetupParticipantTargetReleaseLease {
    pub(crate) const fn participant_identity(&self) -> [u8; 64] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) fn limb_count(&self) -> usize {
        self.ordered_limbs.len()
    }

    pub(crate) fn memory_byte_lengths_from_dimensions(
        limb_count: usize,
        canonical_coefficient_count: usize,
    ) -> CanonicalResult<(u64, u64)> {
        if limb_count == 0 || canonical_coefficient_count == 0 {
            return Err(authority_binding_error());
        }
        let unique_owned_heap_byte_length =
            target_release_lease_unique_owned_heap_byte_length(limb_count)?;
        let allocation_byte_lengths =
            authenticated_committed_material_shared_allocation_byte_lengths(
                canonical_coefficient_count,
            )
            .map_err(|_| authority_binding_error())?;
        let one_limb_shared_allocation_byte_length = allocation_byte_lengths
            .compact_source()
            .checked_add(allocation_byte_lengths.canonical_message())
            .ok_or_else(authority_binding_error)?;
        let shared_allocation_byte_length = u64::try_from(limb_count)
            .ok()
            .and_then(|count| count.checked_mul(one_limb_shared_allocation_byte_length))
            .ok_or_else(authority_binding_error)?;
        Ok((unique_owned_heap_byte_length, shared_allocation_byte_length))
    }

    pub(crate) fn memory_accounting(
        &self,
    ) -> CanonicalResult<VerifiedAcceptedSetupParticipantTargetReleaseLeaseMemoryAccounting> {
        let unique_owned_heap_byte_length =
            target_release_lease_unique_owned_heap_byte_length(self.ordered_limbs.len())?;
        let mut shared_allocation_byte_lengths = BTreeMap::<usize, u64>::new();
        for limb in &self.ordered_limbs {
            let memory = limb
                .committed_share
                .shared_memory_accounting()
                .map_err(|_| authority_binding_error())?;
            for allocation in [memory.compact_source(), memory.canonical_message()] {
                match shared_allocation_byte_lengths.get(&allocation.owner_identifier()) {
                    Some(byte_length) if *byte_length != allocation.retained_byte_length() => {
                        return Err(authority_binding_error());
                    }
                    Some(_) => {}
                    None => {
                        shared_allocation_byte_lengths.insert(
                            allocation.owner_identifier(),
                            allocation.retained_byte_length(),
                        );
                    }
                }
            }
        }
        let shared_allocations = shared_allocation_byte_lengths
            .into_iter()
            .map(|(owner_identifier, retained_byte_length)| {
                CommittedMaterialSharedAllocationMemoryAccounting::new(
                    owner_identifier,
                    retained_byte_length,
                )
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Ok(
            VerifiedAcceptedSetupParticipantTargetReleaseLeaseMemoryAccounting {
                unique_owned_heap_byte_length,
                shared_allocations,
            },
        )
    }

    pub(crate) fn with_limb<Output>(
        &self,
        limb_ordinal: usize,
        operation: impl FnOnce(u16, u64, &[u64], &CompactCommittedMaterialSource) -> Output,
    ) -> Option<Output> {
        let limb = self.ordered_limbs.get(limb_ordinal)?;
        Some(operation(
            limb.data_modulus_index,
            limb.modulus,
            limb.committed_share.canonical_message(),
            limb.committed_share.compact_source(),
        ))
    }
}

/// Non-serializable local opening source for the six selected target limbs.
/// The corresponding public roots remain in the accepted participant record;
/// this source supplies only the positively joined private openings needed by
/// the target-release prover.
pub(crate) struct VerifiedAcceptedSetupParticipantTargetReleaseSource {
    participant_identity: [u8; 64],
    roster_position: u16,
    ordered_limbs: Box<[VerifiedAcceptedSetupParticipantTargetReleaseLimb]>,
}

impl VerifiedAcceptedSetupParticipantTargetReleaseSource {
    pub(super) fn from_verified_aggregate_threshold_share(
        terminal: &VerifiedAggregateThresholdShareTerminal,
        browser_owned_limbs: Vec<BrowserOwnedAggregateThresholdShareLimb>,
    ) -> CanonicalResult<Self> {
        let selected_target_coordinates =
            selected_target_data_prime_coordinates().map_err(|_| authority_binding_error())?;
        let selected_sharing_coordinates =
            selected_sharing_data_prime_coordinates().map_err(|_| authority_binding_error())?;
        if browser_owned_limbs.len() != selected_target_coordinates.len()
            || selected_target_coordinates != selected_sharing_coordinates
            || terminal.ordered_aggregate_threshold_roots().len()
                != selected_sharing_coordinates.len()
        {
            return Err(authority_binding_error());
        }
        let selected_profile =
            selected_committed_material_profile().map_err(|_| authority_binding_error())?;
        let mut ordered_limbs = Vec::with_capacity(selected_target_coordinates.len());
        for (sharing_limb_ordinal, (browser_owned_limb, (expected_data_modulus_index, modulus))) in
            browser_owned_limbs
                .into_iter()
                .zip(selected_target_coordinates.iter().copied())
                .enumerate()
        {
            let expected_context_hash = CommittedMaterialContext::new(
                terminal.suite_identifier(),
                terminal.ceremony_context_hash(),
                terminal.action_context_hash(),
                terminal.participant_identity(),
                CommittedMaterialRole::AggregateThresholdShare,
                expected_data_modulus_index,
                terminal.roster_position(),
            )
            .context_hash()
            .map_err(|_| authority_binding_error())?;
            let committed_share = browser_owned_limb
                .committed_share
                .owned_authenticated_source();
            if browser_owned_limb.data_modulus_index != expected_data_modulus_index
                || committed_share.compact_source().profile() != selected_profile
                || committed_share.compact_source().material_context_hash() != expected_context_hash
                || committed_share.compact_source().root()
                    != terminal.ordered_aggregate_threshold_roots()[sharing_limb_ordinal]
                || committed_share.canonical_message().len() != POLYNOMIAL_DEGREE
                || committed_share
                    .canonical_message()
                    .iter()
                    .any(|coefficient| *coefficient >= modulus)
                || !committed_share
                    .authenticates_canonical_message(committed_share.canonical_message(), modulus)
            {
                return Err(authority_binding_error());
            }
            ordered_limbs.push(VerifiedAcceptedSetupParticipantTargetReleaseLimb {
                data_modulus_index: expected_data_modulus_index,
                modulus,
                committed_share,
            });
        }
        Ok(Self {
            participant_identity: terminal.participant_identity(),
            roster_position: terminal.roster_position(),
            ordered_limbs: ordered_limbs.into_boxed_slice(),
        })
    }

    pub(crate) const fn participant_identity(&self) -> [u8; 64] {
        self.participant_identity
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.roster_position
    }

    pub(crate) fn ordered_limbs(&self) -> &[VerifiedAcceptedSetupParticipantTargetReleaseLimb] {
        &self.ordered_limbs
    }

    fn lease(&self) -> VerifiedAcceptedSetupParticipantTargetReleaseLease {
        VerifiedAcceptedSetupParticipantTargetReleaseLease {
            participant_identity: self.participant_identity,
            roster_position: self.roster_position,
            ordered_limbs: self
                .ordered_limbs
                .iter()
                .map(
                    |limb| VerifiedAcceptedSetupParticipantTargetReleaseLeaseLimb {
                        data_modulus_index: limb.data_modulus_index,
                        modulus: limb.modulus,
                        committed_share: limb.committed_share.clone(),
                    },
                )
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        }
    }
}

/// Compact verifier authority retained after every required setup proof and
/// source binding has completed. It deliberately retains no proof bytes,
/// claimed verdict, or caller-provided setup record.
pub(crate) struct VerifiedAcceptedSetupAuthority {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    manifest_hash: [u8; 64],
    roster_hash: [u8; 64],
    setup_proof_context_hash: [u8; 64],
    exact_verified_setup_source_hash: [u8; 64],
    ring_degree: usize,
    ordered_data_modulus_indices: Box<[u16]>,
    ordered_data_moduli: Box<[u64]>,
    participant_release_materials:
        BTreeMap<[u8; 64], VerifiedAcceptedSetupParticipantReleaseMaterial>,
    participant_target_release_sources:
        BTreeMap<[u8; 64], VerifiedAcceptedSetupParticipantTargetReleaseSource>,
    collective_public_key_root: [u8; 64],
    collective_public_key_full_object_digest: [u8; 64],
    collective_public_key_b_polynomials: Box<[Arc<[u64]>]>,
    public_setup_seed: [u8; 64],
    verified_evaluator_key_store: Option<VerifiedEvaluatorKeyStore>,
}

/// Opaque, non-serializable authority for the public common components needed
/// during evaluator-key replay. It is retained from one accepted setup after
/// the complete setup context has been checked, so transport bytes cannot
/// substitute a different setup seed while a browser replay is paused.
#[derive(Clone)]
pub(crate) struct VerifiedEvaluatorCommonComponentAuthority {
    evaluator_replay_context_hash: [u8; 64],
    public_setup_seed: [u8; 64],
    ring_degree: usize,
}

/// One-shot evaluator authority taken atomically from a retained accepted
/// setup. It keeps the pre-package proof binding, package source hash, and
/// post-package replay context distinct while transferring the sole verified
/// physical store to the evaluator.
pub(crate) struct VerifiedEvaluatorExecutionAuthority {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    manifest_hash: [u8; 64],
    roster_hash: [u8; 64],
    setup_proof_context_hash: [u8; 64],
    evaluator_replay_context_hash: [u8; 64],
    common_component_authority: VerifiedEvaluatorCommonComponentAuthority,
    verified_store: VerifiedEvaluatorKeyStore,
}

impl VerifiedEvaluatorExecutionAuthority {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; 64] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; 64] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; 64] {
        self.action_context_hash
    }

    pub(crate) const fn manifest_hash(&self) -> [u8; 64] {
        self.manifest_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; 64] {
        self.roster_hash
    }

    pub(crate) const fn setup_proof_context_hash(&self) -> [u8; 64] {
        self.setup_proof_context_hash
    }

    pub(crate) const fn evaluator_replay_context_hash(&self) -> [u8; 64] {
        self.evaluator_replay_context_hash
    }

    pub(crate) const fn top_count(&self) -> u16 {
        self.verified_store.top_count()
    }

    pub(crate) fn into_store_and_common_component_authority(
        self,
    ) -> (
        VerifiedEvaluatorKeyStore,
        VerifiedEvaluatorCommonComponentAuthority,
    ) {
        (self.verified_store, self.common_component_authority)
    }
}

impl VerifiedEvaluatorCommonComponentAuthority {
    pub(crate) const fn evaluator_replay_context_hash(&self) -> [u8; 64] {
        self.evaluator_replay_context_hash
    }

    pub(crate) fn sample_galois_common_component_limb(
        &self,
        position: SelectedEvaluatorEntryPosition,
        decomposition_block_index: usize,
        extended_limb_index: usize,
    ) -> CanonicalResult<Vec<u64>> {
        sample_evaluator_galois_common_component_limb(
            &self.public_setup_seed,
            self.ring_degree,
            position,
            decomposition_block_index,
            extended_limb_index,
        )
    }
}

impl VerifiedAcceptedSetupAuthority {
    pub(crate) const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub(crate) const fn suite_identifier(&self) -> [u8; 64] {
        self.suite_identifier
    }

    pub(crate) const fn ceremony_context_hash(&self) -> [u8; 64] {
        self.ceremony_context_hash
    }

    pub(crate) const fn action_context_hash(&self) -> [u8; 64] {
        self.action_context_hash
    }

    pub(crate) const fn roster_hash(&self) -> [u8; 64] {
        self.roster_hash
    }

    pub(crate) const fn exact_verified_setup_source_hash(&self) -> [u8; 64] {
        self.exact_verified_setup_source_hash
    }

    pub(crate) const fn ring_degree(&self) -> usize {
        self.ring_degree
    }

    pub(crate) fn verified_evaluator_top_count(&self) -> Option<u16> {
        self.verified_evaluator_key_store
            .as_ref()
            .map(VerifiedEvaluatorKeyStore::top_count)
    }

    pub(crate) fn ordered_data_modulus_indices(&self) -> &[u16] {
        &self.ordered_data_modulus_indices
    }

    pub(crate) fn ordered_data_moduli(&self) -> &[u64] {
        &self.ordered_data_moduli
    }

    pub(crate) fn participant_release_material(
        &self,
        participant_identity: [u8; 64],
    ) -> Option<&VerifiedAcceptedSetupParticipantReleaseMaterial> {
        self.participant_release_materials
            .get(&participant_identity)
    }

    fn participant_target_release_source(
        &self,
        participant_identity: [u8; 64],
    ) -> Option<&VerifiedAcceptedSetupParticipantTargetReleaseSource> {
        self.participant_target_release_sources
            .get(&participant_identity)
    }

    pub(crate) const fn collective_public_key_root(&self) -> [u8; 64] {
        self.collective_public_key_root
    }

    pub(crate) fn begin_collective_public_key_readback(
        &self,
    ) -> CanonicalResult<VerifiedCollectivePublicKeyReadback> {
        VerifiedCollectivePublicKeyReadback::new(self)
    }

    /// Recomputes the evaluator context from the accepted canonical-board
    /// source. The setup seed remains inside this opaque authority; a detached
    /// transport seed hash cannot recreate the binding.
    pub(crate) fn evaluator_replay_context_hash(&self) -> CanonicalResult<[u8; 64]> {
        hash_foundation_tuple_512(
            EVALUATOR_REPLAY_CONTEXT_HASH_DOMAIN,
            &[
                CanonicalItem::unsigned16(self.protocol_version),
                CanonicalItem::hash512(self.suite_identifier),
                CanonicalItem::hash512(self.ceremony_context_hash),
                CanonicalItem::hash512(self.action_context_hash),
                CanonicalItem::hash512(self.roster_hash),
                CanonicalItem::hash512(self.exact_verified_setup_source_hash),
                CanonicalItem::hash512(self.public_setup_seed),
            ],
        )
        .map(Hash512::into_bytes)
        .map_err(|error| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidProtocolObject,
                format!("evaluator replay context encoding failed: {error}"),
            )
        })
    }

    pub(crate) fn retain_evaluator_common_component_authority(
        &self,
    ) -> CanonicalResult<VerifiedEvaluatorCommonComponentAuthority> {
        Ok(VerifiedEvaluatorCommonComponentAuthority {
            evaluator_replay_context_hash: self.evaluator_replay_context_hash()?,
            public_setup_seed: self.public_setup_seed,
            ring_degree: self.ring_degree,
        })
    }
}

fn sample_evaluator_galois_common_component_limb(
    public_setup_seed: &[u8; 64],
    ring_degree: usize,
    position: SelectedEvaluatorEntryPosition,
    decomposition_block_index: usize,
    extended_limb_index: usize,
) -> CanonicalResult<Vec<u64>> {
    let SelectedEvaluatorEntryKind::Galois { catalog_level, .. } = position.key_kind() else {
        return Err(authority_binding_error());
    };
    let topology = KeySwitchDecompositionTopology::for_level(catalog_level)?;
    if decomposition_block_index >= topology.data_block_count()
        || extended_limb_index >= topology.extended_limb_count()
    {
        return Err(authority_binding_error());
    }
    let (modulus_catalog_identifier, modulus_index) =
        if extended_limb_index < topology.data_prime_count() {
            (
                DATA_MODULUS_CATALOG_IDENTIFIER,
                u16::try_from(extended_limb_index).map_err(|_| authority_size_error())?,
            )
        } else {
            (
                SPECIAL_MODULUS_CATALOG_IDENTIFIER,
                u16::try_from(extended_limb_index - topology.data_prime_count())
                    .map_err(|_| authority_size_error())?,
            )
        };
    sample_galois_common_reference_limb(
        public_setup_seed,
        position.schedule_position(),
        u16::try_from(decomposition_block_index).map_err(|_| authority_size_error())?,
        modulus_catalog_identifier,
        modulus_index,
        ring_degree,
    )
}

pub(crate) struct VerifiedCollectivePublicKeyPolynomial {
    component_ordinal: u16,
    data_modulus_index: u16,
    modulus: u64,
    coefficients: Arc<[u64]>,
}

impl VerifiedCollectivePublicKeyPolynomial {
    pub(crate) const fn component_ordinal(&self) -> u16 {
        self.component_ordinal
    }

    pub(crate) const fn data_modulus_index(&self) -> u16 {
        self.data_modulus_index
    }

    pub(crate) const fn modulus(&self) -> u64 {
        self.modulus
    }

    pub(crate) fn coefficients(&self) -> &Arc<[u64]> {
        &self.coefficients
    }
}

/// One reset-safe, forward-only pass over the exact accepted collective key.
/// Every pass re-authenticates the complete b-then-a byte stream at finish.
pub(crate) struct VerifiedCollectivePublicKeyReadback {
    ring_degree: usize,
    ordered_data_modulus_indices: Box<[u16]>,
    ordered_data_moduli: Box<[u64]>,
    collective_public_key_b_polynomials: Box<[Arc<[u64]>]>,
    public_setup_seed: [u8; 64],
    expected_full_object_digest: [u8; 64],
    next_polynomial_ordinal: usize,
    digest_accumulator: CollectivePublicKeyDigestAccumulator,
}

impl VerifiedCollectivePublicKeyReadback {
    fn new(authority: &VerifiedAcceptedSetupAuthority) -> CanonicalResult<Self> {
        Ok(Self {
            ring_degree: authority.ring_degree,
            ordered_data_modulus_indices: authority.ordered_data_modulus_indices.clone(),
            ordered_data_moduli: authority.ordered_data_moduli.clone(),
            collective_public_key_b_polynomials: authority
                .collective_public_key_b_polynomials
                .clone(),
            public_setup_seed: authority.public_setup_seed,
            expected_full_object_digest: authority.collective_public_key_full_object_digest,
            next_polynomial_ordinal: 0,
            digest_accumulator: CollectivePublicKeyDigestAccumulator::new(
                authority.ring_degree,
                authority.ordered_data_moduli.len(),
            )?,
        })
    }

    pub(crate) fn next_polynomial(
        &mut self,
    ) -> CanonicalResult<Option<VerifiedCollectivePublicKeyPolynomial>> {
        let modulus_count = self.ordered_data_moduli.len();
        let polynomial_count = modulus_count
            .checked_mul(COLLECTIVE_PUBLIC_KEY_COMPONENT_COUNT)
            .ok_or_else(authority_size_error)?;
        if self.next_polynomial_ordinal == polynomial_count {
            return Ok(None);
        }
        if self.next_polynomial_ordinal > polynomial_count {
            return Err(authority_state_error(
                "collective public-key readback advanced past its exact sequence",
            ));
        }

        let component_ordinal = self.next_polynomial_ordinal / modulus_count;
        let modulus_ordinal = self.next_polynomial_ordinal % modulus_count;
        let data_modulus_index = self.ordered_data_modulus_indices[modulus_ordinal];
        let modulus = self.ordered_data_moduli[modulus_ordinal];
        let coefficients: Arc<[u64]> = match component_ordinal {
            0 => Arc::clone(&self.collective_public_key_b_polynomials[modulus_ordinal]),
            1 => sample_collective_public_key_common_reference_limb(
                &self.public_setup_seed,
                data_modulus_index,
                self.ring_degree,
            )?
            .into(),
            _ => {
                return Err(authority_state_error(
                    "collective public-key readback selected an unknown component",
                ));
            }
        };
        validate_polynomial(&coefficients, self.ring_degree, modulus)?;
        self.digest_accumulator.absorb_polynomial(&coefficients)?;
        self.next_polynomial_ordinal = self
            .next_polynomial_ordinal
            .checked_add(1)
            .ok_or_else(authority_size_error)?;
        Ok(Some(VerifiedCollectivePublicKeyPolynomial {
            component_ordinal: if component_ordinal == 0 {
                COLLECTIVE_PUBLIC_KEY_B_COMPONENT_ORDINAL
            } else {
                COLLECTIVE_PUBLIC_KEY_COMMON_REFERENCE_COMPONENT_ORDINAL
            },
            data_modulus_index,
            modulus,
            coefficients,
        }))
    }

    pub(crate) fn finish(self) -> CanonicalResult<()> {
        let expected_polynomial_count = self
            .ordered_data_moduli
            .len()
            .checked_mul(COLLECTIVE_PUBLIC_KEY_COMPONENT_COUNT)
            .ok_or_else(authority_size_error)?;
        if self.next_polynomial_ordinal != expected_polynomial_count {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "collective public-key readback did not consume the complete exact sequence",
            ));
        }
        let observed_descriptor = self.digest_accumulator.finish()?;
        if observed_descriptor.full_object_digest.into_bytes() != self.expected_full_object_digest {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "collective public-key readback does not match the proof-bound full-object digest",
            ));
        }
        Ok(())
    }
}

struct CollectivePublicKeyDigestAccumulator {
    writer: CanonicalStreamWriter,
    pending_chunk: Vec<u8>,
    next_chunk_index: usize,
}

impl CollectivePublicKeyDigestAccumulator {
    fn new(ring_degree: usize, modulus_count: usize) -> CanonicalResult<Self> {
        let total_byte_length = ring_degree
            .checked_mul(modulus_count)
            .and_then(|count| count.checked_mul(COLLECTIVE_PUBLIC_KEY_COMPONENT_COUNT))
            .and_then(|count| count.checked_mul(size_of::<u64>()))
            .and_then(|count| u64::try_from(count).ok())
            .ok_or_else(authority_size_error)?;
        let writer = CanonicalStreamWriter::new(
            CanonicalStreamDomain::CollectivePublicKey,
            total_byte_length,
        )
        .map_err(canonical_stream_error)?;
        Ok(Self {
            writer,
            pending_chunk: Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length),
            next_chunk_index: 0,
        })
    }

    fn absorb_polynomial(&mut self, coefficients: &[u64]) -> CanonicalResult<()> {
        for coefficient in coefficients {
            self.absorb_bytes(&coefficient.to_le_bytes())?;
        }
        Ok(())
    }

    fn absorb_bytes(&mut self, mut bytes: &[u8]) -> CanonicalResult<()> {
        while !bytes.is_empty() {
            let remaining_chunk_capacity = FOUNDATION_PROFILE
                .stream_chunk_byte_length
                .checked_sub(self.pending_chunk.len())
                .ok_or_else(authority_size_error)?;
            let copied_byte_count = remaining_chunk_capacity.min(bytes.len());
            self.pending_chunk
                .extend_from_slice(&bytes[..copied_byte_count]);
            bytes = &bytes[copied_byte_count..];
            if self.pending_chunk.len() == FOUNDATION_PROFILE.stream_chunk_byte_length {
                self.writer
                    .absorb_chunk(self.next_chunk_index, &self.pending_chunk)
                    .map_err(canonical_stream_error)?;
                self.next_chunk_index = self
                    .next_chunk_index
                    .checked_add(1)
                    .ok_or_else(authority_size_error)?;
                self.pending_chunk.clear();
            }
        }
        Ok(())
    }

    fn finish(mut self) -> CanonicalResult<crate::foundation::StreamDescriptor> {
        if !self.pending_chunk.is_empty() {
            self.writer
                .absorb_chunk(self.next_chunk_index, &self.pending_chunk)
                .map_err(canonical_stream_error)?;
        }
        self.writer.finish().map_err(canonical_stream_error)
    }
}

pub(super) fn verified_collective_public_key_stream_descriptor(
    terminal: &VerifiedCollectivePublicKeyTerminal,
    public_setup_seed: [u8; Hash512::BYTE_LENGTH],
) -> CanonicalResult<crate::foundation::StreamDescriptor> {
    let mut digest_accumulator =
        CollectivePublicKeyDigestAccumulator::new(POLYNOMIAL_DEGREE, DATA_PRIMES.len())?;
    for polynomial in terminal.collective_public_key_b_polynomials() {
        digest_accumulator.absorb_polynomial(polynomial)?;
    }
    for data_modulus_index in 0..DATA_PRIMES.len() {
        let data_modulus_index =
            u16::try_from(data_modulus_index).map_err(|_| authority_size_error())?;
        let coefficients = sample_collective_public_key_common_reference_limb(
            &public_setup_seed,
            data_modulus_index,
            POLYNOMIAL_DEGREE,
        )?;
        digest_accumulator.absorb_polynomial(&coefficients)?;
    }
    digest_accumulator.finish()
}

pub(super) struct VerifiedAcceptedSetupAuthorityInput {
    pub(super) protocol_version: u16,
    pub(super) suite_identifier: [u8; 64],
    pub(super) ceremony_context_hash: [u8; 64],
    pub(super) action_context_hash: [u8; 64],
    pub(super) manifest_hash: [u8; 64],
    pub(super) roster_hash: [u8; 64],
    pub(super) setup_proof_context_hash: [u8; 64],
    pub(super) exact_verified_setup_source_hash: [u8; 64],
    pub(super) ring_degree: usize,
    pub(super) ordered_data_modulus_indices: Vec<u16>,
    pub(super) ordered_data_moduli: Vec<u64>,
    pub(super) participant_release_materials: Vec<VerifiedAcceptedSetupParticipantReleaseMaterial>,
    pub(super) participant_target_release_sources:
        Vec<VerifiedAcceptedSetupParticipantTargetReleaseSource>,
    pub(super) collective_public_key_root: [u8; 64],
    pub(super) collective_public_key_full_object_digest: [u8; 64],
    pub(super) collective_public_key_b_polynomials: Vec<Arc<[u64]>>,
    pub(super) public_setup_seed: [u8; 64],
}

pub(super) struct VerifiedAcceptedSetupAuthorityBorrowedInput<'input> {
    pub(super) protocol_version: u16,
    pub(super) suite_identifier: [u8; 64],
    pub(super) ceremony_context_hash: [u8; 64],
    pub(super) action_context_hash: [u8; 64],
    pub(super) manifest_hash: [u8; 64],
    pub(super) roster_hash: [u8; 64],
    pub(super) setup_proof_context_hash: [u8; 64],
    pub(super) ring_degree: usize,
    pub(super) ordered_data_modulus_indices: &'input [u16],
    pub(super) ordered_data_moduli: &'input [u64],
    pub(super) participant_release_materials:
        &'input [VerifiedAcceptedSetupParticipantReleaseMaterial],
    pub(super) participant_target_release_sources:
        &'input [VerifiedAcceptedSetupParticipantTargetReleaseSource],
    pub(super) collective_public_key_full_object_digest: [u8; 64],
    pub(super) collective_public_key_b_polynomials: &'input [Arc<[u64]>],
    pub(super) public_setup_seed: [u8; 64],
}

impl VerifiedAcceptedSetupAuthority {
    #[cfg(test)]
    fn from_verified_terminals(
        input: VerifiedAcceptedSetupAuthorityInput,
        verified_evaluator_key_store: Option<VerifiedEvaluatorKeyStore>,
    ) -> CanonicalResult<Self> {
        validate_verified_accepted_setup_authority_borrowed(
            VerifiedAcceptedSetupAuthorityBorrowedInput {
                protocol_version: input.protocol_version,
                suite_identifier: input.suite_identifier,
                ceremony_context_hash: input.ceremony_context_hash,
                action_context_hash: input.action_context_hash,
                manifest_hash: input.manifest_hash,
                roster_hash: input.roster_hash,
                setup_proof_context_hash: input.setup_proof_context_hash,
                ring_degree: input.ring_degree,
                ordered_data_modulus_indices: &input.ordered_data_modulus_indices,
                ordered_data_moduli: &input.ordered_data_moduli,
                participant_release_materials: &input.participant_release_materials,
                participant_target_release_sources: &input.participant_target_release_sources,
                collective_public_key_full_object_digest: input
                    .collective_public_key_full_object_digest,
                collective_public_key_b_polynomials: &input.collective_public_key_b_polynomials,
                public_setup_seed: input.public_setup_seed,
            },
            verified_evaluator_key_store.as_ref(),
        )?;
        Ok(Self::from_preflighted_terminals(
            input,
            verified_evaluator_key_store,
        ))
    }

    fn from_preflighted_terminals(
        input: VerifiedAcceptedSetupAuthorityInput,
        verified_evaluator_key_store: Option<VerifiedEvaluatorKeyStore>,
    ) -> Self {
        let participant_release_materials = input
            .participant_release_materials
            .into_iter()
            .map(|material| (material.participant_identity, material))
            .collect();
        let participant_target_release_sources = input
            .participant_target_release_sources
            .into_iter()
            .map(|source| (source.participant_identity, source))
            .collect();

        Self {
            protocol_version: input.protocol_version,
            suite_identifier: input.suite_identifier,
            ceremony_context_hash: input.ceremony_context_hash,
            action_context_hash: input.action_context_hash,
            manifest_hash: input.manifest_hash,
            roster_hash: input.roster_hash,
            setup_proof_context_hash: input.setup_proof_context_hash,
            exact_verified_setup_source_hash: input.exact_verified_setup_source_hash,
            ring_degree: input.ring_degree,
            ordered_data_modulus_indices: input.ordered_data_modulus_indices.into_boxed_slice(),
            ordered_data_moduli: input.ordered_data_moduli.into_boxed_slice(),
            participant_release_materials,
            participant_target_release_sources,
            collective_public_key_root: input.collective_public_key_root,
            collective_public_key_full_object_digest: input
                .collective_public_key_full_object_digest,
            collective_public_key_b_polynomials: input
                .collective_public_key_b_polynomials
                .into_boxed_slice(),
            public_setup_seed: input.public_setup_seed,
            verified_evaluator_key_store,
        }
    }
}

fn validate_verified_accepted_setup_authority_borrowed(
    input: VerifiedAcceptedSetupAuthorityBorrowedInput<'_>,
    verified_evaluator_key_store: Option<&VerifiedEvaluatorKeyStore>,
) -> CanonicalResult<()> {
    validate_selected_basis(
        input.ring_degree,
        input.ordered_data_modulus_indices,
        input.ordered_data_moduli,
    )?;
    if input.protocol_version != FOUNDATION_PROFILE.protocol_version
        || input.collective_public_key_b_polynomials.len() != input.ordered_data_moduli.len()
    {
        return Err(authority_binding_error());
    }
    for (polynomial, modulus) in input
        .collective_public_key_b_polynomials
        .iter()
        .zip(input.ordered_data_moduli)
    {
        validate_polynomial(polynomial, input.ring_degree, *modulus)?;
    }
    let selected_sharing_limb_count = selected_sharing_data_prime_coordinates()
        .map_err(|_| authority_binding_error())?
        .len();
    validate_participant_release_materials_borrowed(
        input.participant_release_materials,
        selected_sharing_limb_count,
    )?;
    validate_participant_target_release_sources_borrowed(
        input.participant_target_release_sources,
        input.participant_release_materials,
    )?;

    let mut digest_accumulator = CollectivePublicKeyDigestAccumulator::new(
        input.ring_degree,
        input.ordered_data_moduli.len(),
    )?;
    for polynomial in input.collective_public_key_b_polynomials {
        digest_accumulator.absorb_polynomial(polynomial)?;
    }
    for data_modulus_index in input.ordered_data_modulus_indices {
        let coefficients = sample_collective_public_key_common_reference_limb(
            &input.public_setup_seed,
            *data_modulus_index,
            input.ring_degree,
        )?;
        digest_accumulator.absorb_polynomial(&coefficients)?;
    }
    if digest_accumulator.finish()?.full_object_digest.into_bytes()
        != input.collective_public_key_full_object_digest
    {
        return Err(authority_binding_error());
    }
    if let Some(verified_store) = verified_evaluator_key_store
        && (verified_store.protocol_version() != input.protocol_version
            || verified_store.suite_identifier() != input.suite_identifier
            || verified_store.ceremony_context_hash() != input.ceremony_context_hash
            || verified_store.action_context_hash() != input.action_context_hash
            || verified_store.manifest_hash() != input.manifest_hash
            || verified_store.roster_hash() != input.roster_hash
            || verified_store.setup_proof_context_hash() != input.setup_proof_context_hash
            || verified_store.proof_stream_descriptor().is_err()
            || verified_store.require_production_replay_material().is_err())
    {
        return Err(authority_binding_error());
    }

    Ok(())
}

fn validate_selected_basis(
    ring_degree: usize,
    ordered_data_modulus_indices: &[u16],
    ordered_data_moduli: &[u64],
) -> CanonicalResult<()> {
    if ring_degree != POLYNOMIAL_DEGREE
        || ordered_data_modulus_indices.len() != DATA_PRIMES.len()
        || ordered_data_moduli.len() != DATA_PRIMES.len()
        || ordered_data_modulus_indices
            .iter()
            .zip(ordered_data_moduli)
            .enumerate()
            .any(|(ordinal, (index, modulus))| {
                usize::from(*index) != ordinal || DATA_PRIMES.get(ordinal) != Some(modulus)
            })
    {
        return Err(authority_binding_error());
    }
    Ok(())
}

fn validate_participant_release_materials_borrowed(
    participant_release_materials: &[VerifiedAcceptedSetupParticipantReleaseMaterial],
    expected_root_count: usize,
) -> CanonicalResult<()> {
    if participant_release_materials.len() != usize::from(FOUNDATION_PROFILE.participant_count) {
        return Err(authority_binding_error());
    }
    let mut roster_positions = BTreeSet::new();
    let mut participant_identities = BTreeSet::new();
    for material in participant_release_materials {
        if usize::from(material.roster_position)
            >= usize::from(FOUNDATION_PROFILE.participant_count)
            || material.ordered_aggregate_threshold_roots.len() != expected_root_count
            || !roster_positions.insert(material.roster_position)
            || !participant_identities.insert(material.participant_identity)
        {
            return Err(authority_binding_error());
        }
    }
    if roster_positions
        .iter()
        .copied()
        .ne(0..FOUNDATION_PROFILE.participant_count)
    {
        return Err(authority_binding_error());
    }
    Ok(())
}

fn validate_participant_target_release_sources_borrowed(
    participant_target_release_sources: &[VerifiedAcceptedSetupParticipantTargetReleaseSource],
    participant_release_materials: &[VerifiedAcceptedSetupParticipantReleaseMaterial],
) -> CanonicalResult<()> {
    let selected_target_coordinates =
        selected_target_data_prime_coordinates().map_err(|_| authority_binding_error())?;
    let selected_sharing_coordinates =
        selected_sharing_data_prime_coordinates().map_err(|_| authority_binding_error())?;
    if participant_target_release_sources.len() > usize::from(FOUNDATION_PROFILE.participant_count)
        || selected_target_coordinates != selected_sharing_coordinates
    {
        return Err(authority_binding_error());
    }
    let selected_profile =
        selected_committed_material_profile().map_err(|_| authority_binding_error())?;
    let mut participant_identities = BTreeSet::new();
    for source in participant_target_release_sources {
        let release_material = participant_release_materials
            .iter()
            .find(|material| material.participant_identity == source.participant_identity)
            .ok_or_else(authority_binding_error)?;
        if source.roster_position != release_material.roster_position
            || source.ordered_limbs.len() != selected_target_coordinates.len()
        {
            return Err(authority_binding_error());
        }
        for (sharing_limb_ordinal, (limb, (expected_data_modulus_index, expected_modulus))) in
            source
                .ordered_limbs
                .iter()
                .zip(selected_target_coordinates.iter().copied())
                .enumerate()
        {
            if limb.data_modulus_index != expected_data_modulus_index
                || limb.modulus != expected_modulus
                || limb.committed_share.compact_source().profile() != selected_profile
                || release_material
                    .ordered_aggregate_threshold_roots
                    .get(sharing_limb_ordinal)
                    .is_none_or(|expected_root| {
                        *expected_root != limb.committed_share.compact_source().root()
                    })
                || limb.committed_share.canonical_message().len() != POLYNOMIAL_DEGREE
                || limb
                    .committed_share
                    .canonical_message()
                    .iter()
                    .any(|coefficient| *coefficient >= expected_modulus)
                || !limb.committed_share.authenticates_canonical_message(
                    limb.committed_share.canonical_message(),
                    expected_modulus,
                )
            {
                return Err(authority_binding_error());
            }
        }
        if !participant_identities.insert(source.participant_identity) {
            return Err(authority_binding_error());
        }
    }
    Ok(())
}

fn validate_polynomial(
    coefficients: &[u64],
    ring_degree: usize,
    modulus: u64,
) -> CanonicalResult<()> {
    if coefficients.len() != ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "collective public-key polynomial length does not match the selected ring",
        ));
    }
    if coefficients
        .iter()
        .any(|coefficient| *coefficient >= modulus)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "collective public-key polynomial contains a noncanonical residue",
        ));
    }
    Ok(())
}

struct VerifiedAcceptedSetupAuthorityRegistry {
    authorities: BTreeMap<u32, VerifiedAcceptedSetupAuthority>,
    next_handle: Option<u32>,
}

impl Default for VerifiedAcceptedSetupAuthorityRegistry {
    fn default() -> Self {
        Self {
            authorities: BTreeMap::new(),
            next_handle: Some(1),
        }
    }
}

impl VerifiedAcceptedSetupAuthorityRegistry {
    fn reserve_handle(&mut self) -> CanonicalResult<u32> {
        let handle = self.next_handle.ok_or_else(|| {
            authority_state_error("accepted-setup authority handles are exhausted")
        })?;
        let next_handle = handle.checked_add(1).ok_or_else(|| {
            authority_state_error("accepted-setup authority handles are exhausted")
        })?;
        if self.authorities.contains_key(&handle) {
            return Err(authority_state_error(
                "accepted-setup authority handle allocation repeated",
            ));
        }
        self.next_handle = Some(next_handle);
        Ok(handle)
    }

    fn commit_reserved(&mut self, handle: u32, authority: VerifiedAcceptedSetupAuthority) {
        assert!(
            self.authorities.insert(handle, authority).is_none(),
            "preflight reserved a unique accepted-setup authority handle"
        );
    }

    #[cfg(test)]
    fn retain(
        &mut self,
        authority: VerifiedAcceptedSetupAuthority,
    ) -> CanonicalResult<VerifiedAcceptedSetupAuthorityHandle> {
        let handle = self.reserve_handle()?;
        self.commit_reserved(handle, authority);
        Ok(VerifiedAcceptedSetupAuthorityHandle(handle))
    }
}

/// Fallible authority construction and handle reservation completed before a
/// state transaction consumes any reservation. Holding the registry guard
/// makes the following insertion infallible and prevents another allocation
/// from taking the reserved handle.
pub(super) struct PreparedVerifiedAcceptedSetupAuthorityCommit {
    registry: MutexGuard<'static, VerifiedAcceptedSetupAuthorityRegistry>,
    handle: u32,
    authority: VerifiedAcceptedSetupAuthority,
}

/// Destination reservation held across accepted-setup source consumption.
/// All authority validation is complete before this token is minted; joining
/// the exact previously borrowed sources below is therefore infallible.
pub(super) struct PreparedVerifiedAcceptedSetupAuthorityDestination {
    registry: MutexGuard<'static, VerifiedAcceptedSetupAuthorityRegistry>,
    handle: u32,
}

impl PreparedVerifiedAcceptedSetupAuthorityDestination {
    pub(super) fn complete(
        self,
        input: VerifiedAcceptedSetupAuthorityInput,
        verified_evaluator_key_store: VerifiedEvaluatorKeyStore,
    ) -> PreparedVerifiedAcceptedSetupAuthorityCommit {
        PreparedVerifiedAcceptedSetupAuthorityCommit {
            registry: self.registry,
            handle: self.handle,
            authority: VerifiedAcceptedSetupAuthority::from_preflighted_terminals(
                input,
                Some(verified_evaluator_key_store),
            ),
        }
    }
}

impl PreparedVerifiedAcceptedSetupAuthorityCommit {
    pub(super) fn commit(self) -> VerifiedAcceptedSetupAuthorityHandle {
        let Self {
            mut registry,
            handle,
            authority,
        } = self;
        registry.commit_reserved(handle, authority);
        VerifiedAcceptedSetupAuthorityHandle(handle)
    }
}

static VERIFIED_ACCEPTED_SETUP_AUTHORITY_REGISTRY: OnceLock<
    Mutex<VerifiedAcceptedSetupAuthorityRegistry>,
> = OnceLock::new();

fn authority_registry() -> &'static Mutex<VerifiedAcceptedSetupAuthorityRegistry> {
    VERIFIED_ACCEPTED_SETUP_AUTHORITY_REGISTRY
        .get_or_init(|| Mutex::new(VerifiedAcceptedSetupAuthorityRegistry::default()))
}

pub(super) fn preflight_verified_accepted_setup_authority_destination(
    input: VerifiedAcceptedSetupAuthorityBorrowedInput<'_>,
    verified_evaluator_key_store: &VerifiedEvaluatorKeyStore,
) -> CanonicalResult<PreparedVerifiedAcceptedSetupAuthorityDestination> {
    validate_verified_accepted_setup_authority_borrowed(input, Some(verified_evaluator_key_store))?;
    let mut registry = authority_registry()
        .lock()
        .map_err(|_| authority_state_error("accepted-setup authority registry is unavailable"))?;
    let handle = registry.reserve_handle()?;
    Ok(PreparedVerifiedAcceptedSetupAuthorityDestination { registry, handle })
}

#[cfg(test)]
fn retain_verified_accepted_setup_authority_without_evaluator_store(
    input: VerifiedAcceptedSetupAuthorityInput,
) -> CanonicalResult<VerifiedAcceptedSetupAuthorityHandle> {
    let authority = VerifiedAcceptedSetupAuthority::from_verified_terminals(input, None)?;
    authority_registry()
        .lock()
        .map_err(|_| authority_state_error("accepted-setup authority registry is unavailable"))?
        .retain(authority)
}

pub(crate) fn with_verified_accepted_setup_authority<Output>(
    handle: &VerifiedAcceptedSetupAuthorityHandle,
    operation: impl FnOnce(&VerifiedAcceptedSetupAuthority) -> CanonicalResult<Output>,
) -> CanonicalResult<Output> {
    let registry = authority_registry()
        .lock()
        .map_err(|_| authority_state_error("accepted-setup authority registry is unavailable"))?;
    let authority = registry.authorities.get(&handle.0).ok_or_else(|| {
        authority_state_error("accepted-setup authority handle is unknown or released")
    })?;
    operation(authority)
}

/// Validates the caller's aggregate binding while the retained authority is
/// locked, derives the post-package common-component context, then atomically
/// transfers the sole verified store. Any validation or derivation failure
/// happens before the store is taken, so a retry cannot inherit partial state.
pub(crate) fn take_verified_evaluator_execution_authority(
    handle: &VerifiedAcceptedSetupAuthorityHandle,
    validate_execution: impl FnOnce(&VerifiedAcceptedSetupAuthority) -> bool,
) -> Result<VerifiedEvaluatorExecutionAuthority, RefusalReason> {
    let mut registry = authority_registry()
        .lock()
        .map_err(|_| RefusalReason::MissingPrerequisite)?;
    let authority = registry
        .authorities
        .get_mut(&handle.0)
        .ok_or(RefusalReason::MissingPrerequisite)?;
    if !validate_execution(authority) {
        return Err(RefusalReason::WrongContext);
    }
    let common_component_authority = authority
        .retain_evaluator_common_component_authority()
        .map_err(|_| RefusalReason::WrongContext)?;
    let evaluator_replay_context_hash = common_component_authority.evaluator_replay_context_hash();
    let verified_store = authority
        .verified_evaluator_key_store
        .take()
        .ok_or(RefusalReason::ConsumedState)?;
    Ok(VerifiedEvaluatorExecutionAuthority {
        protocol_version: authority.protocol_version,
        suite_identifier: authority.suite_identifier,
        ceremony_context_hash: authority.ceremony_context_hash,
        action_context_hash: authority.action_context_hash,
        manifest_hash: authority.manifest_hash,
        roster_hash: authority.roster_hash,
        setup_proof_context_hash: authority.setup_proof_context_hash,
        evaluator_replay_context_hash,
        common_component_authority,
        verified_store,
    })
}

pub(crate) fn with_verified_participant_target_release_source<Output>(
    handle: &VerifiedAcceptedSetupAuthorityHandle,
    participant_identity: [u8; 64],
    operation: impl FnOnce(
        &VerifiedAcceptedSetupAuthority,
        &VerifiedAcceptedSetupParticipantTargetReleaseSource,
    ) -> CanonicalResult<Output>,
) -> CanonicalResult<Output> {
    let registry = authority_registry()
        .lock()
        .map_err(|_| authority_state_error("accepted-setup authority registry is unavailable"))?;
    let authority = registry.authorities.get(&handle.0).ok_or_else(|| {
        authority_state_error("accepted-setup authority handle is unknown or released")
    })?;
    let source = authority
        .participant_target_release_source(participant_identity)
        .ok_or_else(|| {
            authority_state_error(
                "accepted-setup authority has no local target-release source for the participant",
            )
        })?;
    operation(authority, source)
}

pub(crate) fn lease_verified_participant_target_release_source(
    handle: &VerifiedAcceptedSetupAuthorityHandle,
    participant_identity: [u8; 64],
) -> CanonicalResult<VerifiedAcceptedSetupParticipantTargetReleaseLease> {
    let registry = authority_registry()
        .lock()
        .map_err(|_| authority_state_error("accepted-setup authority registry is unavailable"))?;
    let authority = registry.authorities.get(&handle.0).ok_or_else(|| {
        authority_state_error("accepted-setup authority handle is unknown or released")
    })?;
    authority
        .participant_target_release_source(participant_identity)
        .map(VerifiedAcceptedSetupParticipantTargetReleaseSource::lease)
        .ok_or_else(|| {
            authority_state_error(
                "accepted-setup authority has no local target-release source for the participant",
            )
        })
}

pub(crate) fn release_verified_accepted_setup_authority(
    handle: VerifiedAcceptedSetupAuthorityHandle,
) -> CanonicalResult<()> {
    authority_registry()
        .lock()
        .map_err(|_| authority_state_error("accepted-setup authority registry is unavailable"))?
        .authorities
        .remove(&handle.0)
        .map(|_| ())
        .ok_or_else(|| {
            authority_state_error("accepted-setup authority handle is unknown or released")
        })
}

fn canonical_stream_error(refusal_reason: RefusalReason) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidProtocolObject,
        format!("collective public-key canonical stream failed: {refusal_reason:?}"),
    )
}

fn authority_size_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::MalformedLength,
        "accepted-setup authority size exceeds the representation safety bound",
    )
}

fn authority_binding_error() -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::ComponentMismatch,
        "accepted-setup verifier terminals do not share one exact selected-suite binding",
    )
}

fn authority_state_error(message: &'static str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidProtocolObject, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected_sharing_limb_count() -> usize {
        selected_sharing_data_prime_coordinates()
            .expect("selected sharing coordinates")
            .len()
    }

    fn deterministic_b_polynomials() -> Vec<Arc<[u64]>> {
        DATA_PRIMES
            .iter()
            .copied()
            .enumerate()
            .map(|(modulus_ordinal, modulus)| {
                (0..POLYNOMIAL_DEGREE)
                    .map(|coefficient_ordinal| {
                        (u64::try_from(coefficient_ordinal)
                            .unwrap()
                            .wrapping_mul(65_537)
                            .wrapping_add(u64::try_from(modulus_ordinal).unwrap() * 97))
                            % modulus
                    })
                    .collect::<Vec<_>>()
                    .into()
            })
            .collect()
    }

    fn participant_release_materials() -> Vec<VerifiedAcceptedSetupParticipantReleaseMaterial> {
        (0..FOUNDATION_PROFILE.participant_count)
            .map(|roster_position| {
                VerifiedAcceptedSetupParticipantReleaseMaterial::from_test_values(
                    [u8::try_from(roster_position + 1).unwrap(); 64],
                    roster_position,
                    (0..selected_sharing_limb_count())
                        .map(|modulus_ordinal| {
                            [u8::try_from(usize::from(roster_position) + modulus_ordinal + 1)
                                .unwrap(); 64]
                        })
                        .collect(),
                )
            })
            .collect()
    }

    fn full_object_digest(b_polynomials: &[Arc<[u64]>], public_setup_seed: &[u8; 64]) -> [u8; 64] {
        let mut accumulator =
            CollectivePublicKeyDigestAccumulator::new(POLYNOMIAL_DEGREE, DATA_PRIMES.len())
                .expect("collective key digest accumulator");
        for polynomial in b_polynomials {
            accumulator
                .absorb_polynomial(polynomial)
                .expect("b polynomial is absorbed");
        }
        for data_modulus_index in 0..DATA_PRIMES.len() {
            let polynomial = sample_collective_public_key_common_reference_limb(
                public_setup_seed,
                u16::try_from(data_modulus_index).unwrap(),
                POLYNOMIAL_DEGREE,
            )
            .expect("common-reference polynomial derives");
            accumulator
                .absorb_polynomial(&polynomial)
                .expect("common-reference polynomial is absorbed");
        }
        accumulator
            .finish()
            .expect("collective key digest")
            .full_object_digest
            .into_bytes()
    }

    fn authority_input(
        derive_bound_full_object_digest: bool,
    ) -> VerifiedAcceptedSetupAuthorityInput {
        let public_setup_seed = [0x5a; 64];
        let b_polynomials = deterministic_b_polynomials();
        let collective_public_key_full_object_digest = if derive_bound_full_object_digest {
            full_object_digest(&b_polynomials, &public_setup_seed)
        } else {
            [0; 64]
        };
        VerifiedAcceptedSetupAuthorityInput {
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            suite_identifier: [0x11; 64],
            ceremony_context_hash: [0x22; 64],
            action_context_hash: [0x33; 64],
            manifest_hash: [0x34; 64],
            roster_hash: [0x44; 64],
            setup_proof_context_hash: [0x45; 64],
            exact_verified_setup_source_hash: [0x55; 64],
            ring_degree: POLYNOMIAL_DEGREE,
            ordered_data_modulus_indices: (0..DATA_PRIMES.len())
                .map(|index| u16::try_from(index).unwrap())
                .collect(),
            ordered_data_moduli: DATA_PRIMES.to_vec(),
            participant_release_materials: participant_release_materials(),
            participant_target_release_sources: Vec::new(),
            collective_public_key_root: [0x66; 64],
            collective_public_key_full_object_digest,
            collective_public_key_b_polynomials: b_polynomials,
            public_setup_seed,
        }
    }

    #[test]
    fn retained_authority_reopens_one_exact_authenticated_collective_key_sequence() {
        let input = authority_input(true);
        let expected_first_b = Arc::clone(&input.collective_public_key_b_polynomials[0]);
        let handle = retain_verified_accepted_setup_authority_without_evaluator_store(input)
            .expect("valid verifier terminals retain authority");
        let (mut first_readback, mut second_readback) =
            with_verified_accepted_setup_authority(&handle, |authority| {
                assert_eq!(
                    authority.protocol_version(),
                    FOUNDATION_PROFILE.protocol_version
                );
                assert_eq!(authority.suite_identifier(), [0x11; 64]);
                assert_eq!(authority.ceremony_context_hash(), [0x22; 64]);
                assert_eq!(authority.action_context_hash(), [0x33; 64]);
                assert_eq!(authority.roster_hash(), [0x44; 64]);
                assert_eq!(authority.exact_verified_setup_source_hash(), [0x55; 64]);
                assert_eq!(authority.ring_degree(), POLYNOMIAL_DEGREE);
                assert_eq!(
                    authority.ordered_data_modulus_indices(),
                    &(0..DATA_PRIMES.len())
                        .map(|data_prime_index| {
                            u16::try_from(data_prime_index).expect("data prime index fits u16")
                        })
                        .collect::<Vec<_>>()
                );
                assert_eq!(authority.ordered_data_moduli(), DATA_PRIMES);
                assert_eq!(authority.collective_public_key_root(), [0x66; 64]);
                let participant = authority
                    .participant_release_material([1; 64])
                    .expect("first roster identity is retained");
                assert_eq!(participant.participant_identity(), [1; 64]);
                assert_eq!(participant.roster_position(), 0);
                assert_eq!(
                    participant.ordered_aggregate_threshold_roots().len(),
                    selected_sharing_limb_count()
                );
                assert_eq!(
                    participant
                        .selected_target_aggregate_threshold_roots()?
                        .as_ref(),
                    &[
                        [1; 64], [2; 64], [3; 64], [4; 64], [5; 64], [6; 64], [7; 64], [8; 64],
                    ]
                );
                Ok((
                    authority.begin_collective_public_key_readback()?,
                    authority.begin_collective_public_key_readback()?,
                ))
            })
            .expect("authority borrow");

        let first_polynomial = first_readback
            .next_polynomial()
            .expect("first readback polynomial")
            .expect("first polynomial exists");
        let reopened_first_polynomial = second_readback
            .next_polynomial()
            .expect("reopened first readback polynomial")
            .expect("reopened first polynomial exists");
        assert_eq!(first_polynomial.component_ordinal(), 0);
        assert_eq!(first_polynomial.data_modulus_index(), 0);
        assert_eq!(first_polynomial.modulus(), DATA_PRIMES[0]);
        assert_eq!(
            first_polynomial.coefficients().as_ref(),
            expected_first_b.as_ref()
        );
        assert_eq!(
            reopened_first_polynomial.coefficients().as_ref(),
            expected_first_b.as_ref()
        );

        while first_readback
            .next_polynomial()
            .expect("complete readback polynomial")
            .is_some()
        {}
        first_readback
            .finish()
            .expect("the complete sequence authenticates");
        assert!(
            second_readback.finish().is_err(),
            "a partial pass cannot authenticate at finish"
        );

        release_verified_accepted_setup_authority(handle).expect("authority releases once");
    }

    #[test]
    fn authority_rejects_wrong_digest_noncanonical_b_and_duplicate_roster_positions() {
        let mut wrong_digest = authority_input(true);
        wrong_digest.collective_public_key_full_object_digest[0] ^= 1;
        assert_eq!(
            VerifiedAcceptedSetupAuthority::from_verified_terminals(wrong_digest, None)
                .err()
                .expect("a substituted full-object digest must fail")
                .code,
            CanonicalErrorCode::ComponentMismatch
        );

        let mut noncanonical_b = authority_input(false);
        noncanonical_b.collective_public_key_b_polynomials[0] =
            vec![DATA_PRIMES[0]; POLYNOMIAL_DEGREE].into();
        assert_eq!(
            VerifiedAcceptedSetupAuthority::from_verified_terminals(noncanonical_b, None)
                .err()
                .expect("a noncanonical b polynomial must fail")
                .code,
            CanonicalErrorCode::InvalidProtocolObject
        );

        let mut duplicate_position = authority_input(false);
        duplicate_position.participant_release_materials[1].roster_position = 0;
        assert_eq!(
            VerifiedAcceptedSetupAuthority::from_verified_terminals(duplicate_position, None)
                .err()
                .expect("duplicate roster positions must fail")
                .code,
            CanonicalErrorCode::ComponentMismatch
        );
    }

    #[test]
    fn authority_registry_reservation_does_not_publish_before_infallible_commit() {
        let authority =
            VerifiedAcceptedSetupAuthority::from_verified_terminals(authority_input(true), None)
                .expect("valid verifier terminals construct authority");
        let mut registry = VerifiedAcceptedSetupAuthorityRegistry::default();
        let reserved_handle = registry.reserve_handle().expect("handle reserves");
        assert!(!registry.authorities.contains_key(&reserved_handle));

        registry.commit_reserved(reserved_handle, authority);
        assert!(registry.authorities.contains_key(&reserved_handle));
        assert_eq!(registry.next_handle, reserved_handle.checked_add(1));
    }
}
