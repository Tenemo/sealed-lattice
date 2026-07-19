//! Browser/WASM runtime authority for selected aggregate threshold shares.
//!
//! The recipient accepts only authenticated canonical mailbox payloads joined
//! to the exact verified dealer terminals. It reconstructs every source tree,
//! derives aggregate seeds from retained action randomness, and exposes no
//! caller-selected statement, root, row, seed, or aggregate coefficient.

use std::{cell::RefCell, collections::BTreeMap, mem::size_of, rc::Rc};

use zeroize::Zeroizing;

use crate::{
    bgv::{
        modular_arithmetic::{add_mod_fast, sub_mod_fast},
        parameters::POLYNOMIAL_DEGREE,
        setup::{
            BrowserOwnedAggregateThresholdShareLimb, GeneratedPrivateVssMailboxCorpusInput,
            SetupGeneratedCommittedMaterial, VerifiedAcceptedSetupVssQualification,
            VerifiedAggregateThresholdShareTerminal,
            VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog, VerifiedPublicRandomness,
            VerifiedVssQualificationTerminals, VerifiedVssShareLinkageTerminal,
            derive_recipient_input_root, verify_public_randomness_board_sources,
        },
    },
    foundation::{
        ActionPrivateRandomness, BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
        CanonicalDecodeLimits, FOUNDATION_PROFILE, FoundationObjectType, FoundationSchemaError,
        Hash512, ParticipantIdentity, PersistentProofCoinInput, PreparedActionProofAttemptSource,
        PrivateRandomnessDomain, PrivateRandomnessKmacInputClassAccounting,
        ProofApplicationBinding, ProofApplicationSlot, ProofApplicationSlotCeilings,
        ProofObjectHeader, RefusalReason, STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH,
        SignedMailboxEnvelope, VerifiedBoardApplicationSource,
        VerifiedStateReservationRuntimeBinding,
        bind_prepared_action_proof_attempt_to_canonical_witness,
        consume_authenticated_mailbox_plaintext_capability,
        resolve_prepared_action_proof_attempt_source, resolve_verified_board_application_sources,
        retain_action_private_randomness_for_exact_family, selected_sharing_data_prime_coordinates,
        selected_target_data_prime_coordinates, verified_state_reservation_binding,
    },
};

use super::{
    CommittedMaterialContext, CommittedMaterialRole, CommittedMaterialSourcePolynomialAdapter,
    CommittedMaterialTree, CommonProofGenerationAuthorization,
    CommonProofGenerationPreparationError, CommonProofGenerationSources,
    CommonProofPrivateCoinCoordinateCapacity, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    CommonProofSelectedSuiteCapabilityHandle, ConsumedVerifiedCommonProofCapability,
    PreparedCommonProofGeneration, PrivateRandomnessCommonProofCoinSource, ProofProfileError,
    RecipientPrivateVssPayloadError, RelationPlanError, SelectedProofAccountingError,
    canonical_selected_aggregate_threshold_share_statement,
    canonical_selected_vss_share_linkage_statement,
    compile_aggregate_threshold_share_relation_plan,
    consume_ordered_verified_vss_share_linkage_terminals, decode_recipient_private_vss_payload,
    maximum_committed_material_kmac_input_accounting, selected_committed_material_profile,
    selected_committed_material_relation_plan_input, selected_proof_runtime_limits,
    selected_relation_plan_check_context, verified_application_statement_hash,
};

use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    bind_generated_common_proof_to_verified_board_source,
    retain_common_proof_generation_family_adapter,
    retain_common_proof_verification_family_adapter_from_upstream,
    with_common_proof_selected_suite,
};

const MATERIAL_SEED_BYTE_LENGTH: usize = 64;
const AGGREGATE_MATERIAL_RANDOMNESS_PURPOSE: u16 = 3;
const EXPECTED_PUBLIC_RANDOMNESS_OBJECTS_PER_PARTICIPANT: usize = 3;
const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;

/// Exact ownership accounting for the canonical aggregate-share coefficients.
/// The committed-material source is the sole retained owner after the final
/// source is absorbed and remains that sole owner in accepted setup state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AggregateThresholdShareCanonicalCoefficientMemoryAccounting {
    retained_before_final_source_byte_length: u64,
    maximum_transient_byte_length: u64,
    retained_after_final_source_byte_length: u64,
    removed_generation_duplicate_byte_length: u64,
    retained_target_release_byte_length: u64,
    removed_persistent_duplicate_byte_length: u64,
}

impl AggregateThresholdShareCanonicalCoefficientMemoryAccounting {
    pub(crate) const fn retained_before_final_source_byte_length(self) -> u64 {
        self.retained_before_final_source_byte_length
    }

    pub(crate) const fn maximum_transient_byte_length(self) -> u64 {
        self.maximum_transient_byte_length
    }

    pub(crate) const fn retained_after_final_source_byte_length(self) -> u64 {
        self.retained_after_final_source_byte_length
    }

    pub(crate) const fn removed_generation_duplicate_byte_length(self) -> u64 {
        self.removed_generation_duplicate_byte_length
    }

    pub(crate) const fn retained_target_release_byte_length(self) -> u64 {
        self.retained_target_release_byte_length
    }

    pub(crate) const fn removed_persistent_duplicate_byte_length(self) -> u64 {
        self.removed_persistent_duplicate_byte_length
    }
}

pub(crate) fn aggregate_threshold_share_canonical_coefficient_memory_accounting() -> Result<
    AggregateThresholdShareCanonicalCoefficientMemoryAccounting,
    AggregateThresholdShareRuntimeError,
> {
    let sharing_limb_count = u64::try_from(selected_vss_sharing_coordinates()?.len())
        .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)?;
    let polynomial_degree = u64::try_from(POLYNOMIAL_DEGREE)
        .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)?;
    let coefficient_byte_length = u64::try_from(size_of::<u64>())
        .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)?;
    let canonical_owner_byte_length = sharing_limb_count
        .checked_mul(polynomial_degree)
        .and_then(|length| length.checked_mul(coefficient_byte_length))
        .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
    let maximum_transient_byte_length = canonical_owner_byte_length
        .checked_mul(2)
        .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
    let removed_generation_duplicate_byte_length = canonical_owner_byte_length
        .checked_mul(2)
        .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;

    Ok(
        AggregateThresholdShareCanonicalCoefficientMemoryAccounting {
            retained_before_final_source_byte_length: canonical_owner_byte_length,
            maximum_transient_byte_length,
            retained_after_final_source_byte_length: canonical_owner_byte_length,
            removed_generation_duplicate_byte_length,
            retained_target_release_byte_length: canonical_owner_byte_length,
            removed_persistent_duplicate_byte_length: canonical_owner_byte_length,
        },
    )
}

fn selected_vss_sharing_coordinates()
-> Result<Box<[(u16, u64)]>, AggregateThresholdShareRuntimeError> {
    selected_sharing_data_prime_coordinates().map_err(Into::into)
}

/// Source-owned count for the aggregate committed-material population created
/// by one recipient. The setup-attempt identifier is shared with all setup
/// streams and is therefore owned by the ceremony-level attempt catalog.
pub(crate) fn aggregate_threshold_share_private_randomness_kmac_input_accounting()
-> Result<PrivateRandomnessKmacInputClassAccounting, AggregateThresholdShareRuntimeError> {
    let profile = selected_committed_material_profile()?;
    let physical_root_count = u64::try_from(selected_vss_sharing_coordinates()?.len())
        .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)?;
    let full_salted_leaf_count = physical_root_count
        .checked_mul(
            u64::try_from(profile.evaluation_domain_size() / 2)
                .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)?,
        )
        .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
    maximum_committed_material_kmac_input_accounting(
        profile,
        physical_root_count,
        full_salted_leaf_count,
    )
    .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)
}

#[derive(Debug)]
pub(crate) enum AggregateThresholdShareRuntimeError {
    Profile(ProofProfileError),
    Accounting(SelectedProofAccountingError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    GenerationPreparation(CommonProofGenerationPreparationError),
    RecipientPayload(RecipientPrivateVssPayloadError),
    Foundation(FoundationSchemaError),
    Refusal(RefusalReason),
    Runtime(CommonProofRuntimeError),
    ActionRandomnessRuntime(u32),
    BoardRuntime(u32),
    MailboxRuntime(u32),
    InvalidInput,
}

impl From<ProofProfileError> for AggregateThresholdShareRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<SelectedProofAccountingError> for AggregateThresholdShareRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<RelationPlanError> for AggregateThresholdShareRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for AggregateThresholdShareRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofGenerationPreparationError> for AggregateThresholdShareRuntimeError {
    fn from(error: CommonProofGenerationPreparationError) -> Self {
        Self::GenerationPreparation(error)
    }
}

impl From<RecipientPrivateVssPayloadError> for AggregateThresholdShareRuntimeError {
    fn from(error: RecipientPrivateVssPayloadError) -> Self {
        Self::RecipientPayload(error)
    }
}

impl From<FoundationSchemaError> for AggregateThresholdShareRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

impl From<RefusalReason> for AggregateThresholdShareRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

impl From<CommonProofRuntimeError> for AggregateThresholdShareRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

struct AggregateThresholdShareGenerationMaterial {
    ordered_aggregate_materials: Box<[SetupGeneratedCommittedMaterial]>,
    canonical_application_statement_bytes: Vec<u8>,
    pinned_proof_attempt: Option<PinnedAggregateProofAttempt>,
}

struct PinnedAggregateProofAttempt {
    attempt_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    application_slot_hash: [u8; 64],
    application_statement_hash: [u8; 64],
}

struct AggregateThresholdShareRecipientAuthority {
    verified_public_randomness: Option<VerifiedPublicRandomness>,
    ordered_dealer_terminals: Option<Vec<VerifiedVssShareLinkageTerminal>>,
    local_recipient_identity: ParticipantIdentity,
    local_recipient_roster_position: u16,
    action_private_randomness: Rc<ActionPrivateRandomness>,
    ordered_source_materials_by_dealer: Box<[Option<Box<[SetupGeneratedCommittedMaterial]>>]>,
    aggregate_share_coefficients: Option<Box<[Zeroizing<Vec<u64>>]>>,
    generation_material: Option<AggregateThresholdShareGenerationMaterial>,
    ordered_recipient_terminals: Box<[Option<VerifiedAggregateThresholdShareTerminal>]>,
    private_vss_mailbox_byte_lengths:
        Option<VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog>,
}

struct AggregateThresholdShareRecipientAuthorityRegistry {
    entries: BTreeMap<u32, AggregateThresholdShareRecipientAuthorityEntry>,
    next_handle: u32,
}

enum AggregateThresholdShareRecipientAuthorityEntry {
    Active(AggregateThresholdShareRecipientAuthority),
    Complete(VerifiedAcceptedSetupVssQualification),
}

impl Default for AggregateThresholdShareRecipientAuthorityRegistry {
    fn default() -> Self {
        Self {
            entries: BTreeMap::new(),
            next_handle: 1,
        }
    }
}

impl AggregateThresholdShareRecipientAuthorityRegistry {
    fn retain(
        &mut self,
        authority: AggregateThresholdShareRecipientAuthority,
    ) -> Result<u32, AggregateThresholdShareRuntimeError> {
        if !self.entries.is_empty() || self.next_handle == 0 {
            return Err(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ));
        }
        let handle = self.next_handle;
        self.next_handle = handle.checked_add(1).filter(|next| *next != 0).ok_or(
            AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ),
        )?;
        self.entries.insert(
            handle,
            AggregateThresholdShareRecipientAuthorityEntry::Active(authority),
        );
        Ok(handle)
    }

    fn authority(
        &self,
        handle: u32,
    ) -> Result<&AggregateThresholdShareRecipientAuthority, AggregateThresholdShareRuntimeError>
    {
        self.entries
            .get(&handle)
            .and_then(|entry| match entry {
                AggregateThresholdShareRecipientAuthorityEntry::Active(authority) => {
                    Some(authority)
                }
                AggregateThresholdShareRecipientAuthorityEntry::Complete(_) => None,
            })
            .ok_or(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }

    fn authority_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut AggregateThresholdShareRecipientAuthority, AggregateThresholdShareRuntimeError>
    {
        self.entries
            .get_mut(&handle)
            .and_then(|entry| match entry {
                AggregateThresholdShareRecipientAuthorityEntry::Active(authority) => {
                    Some(authority)
                }
                AggregateThresholdShareRecipientAuthorityEntry::Complete(_) => None,
            })
            .ok_or(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }

    fn take_active(
        &mut self,
        handle: u32,
    ) -> Result<AggregateThresholdShareRecipientAuthority, AggregateThresholdShareRuntimeError>
    {
        match self
            .entries
            .remove(&handle)
            .ok_or(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))? {
            AggregateThresholdShareRecipientAuthorityEntry::Active(authority) => Ok(authority),
            complete @ AggregateThresholdShareRecipientAuthorityEntry::Complete(_) => {
                self.entries.insert(handle, complete);
                Err(AggregateThresholdShareRuntimeError::Runtime(
                    CommonProofRuntimeError::WrongOperationPhase,
                ))
            }
        }
    }

    fn complete(
        &mut self,
        handle: u32,
        qualification: VerifiedAcceptedSetupVssQualification,
    ) -> Result<(), AggregateThresholdShareRuntimeError> {
        if self.entries.contains_key(&handle) {
            return Err(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::WrongOperationPhase,
            ));
        }
        self.entries.insert(
            handle,
            AggregateThresholdShareRecipientAuthorityEntry::Complete(qualification),
        );
        Ok(())
    }

    fn consume_complete(
        &mut self,
        handle: u32,
    ) -> Result<VerifiedAcceptedSetupVssQualification, AggregateThresholdShareRuntimeError> {
        match self
            .entries
            .remove(&handle)
            .ok_or(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))? {
            AggregateThresholdShareRecipientAuthorityEntry::Complete(qualification) => {
                Ok(qualification)
            }
            active @ AggregateThresholdShareRecipientAuthorityEntry::Active(_) => {
                self.entries.insert(handle, active);
                Err(AggregateThresholdShareRuntimeError::Runtime(
                    CommonProofRuntimeError::WrongOperationPhase,
                ))
            }
        }
    }

    fn with_complete<Output>(
        &self,
        handle: u32,
        inspect: impl FnOnce(&VerifiedAcceptedSetupVssQualification) -> Output,
    ) -> Result<Output, AggregateThresholdShareRuntimeError> {
        match self
            .entries
            .get(&handle)
            .ok_or(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))? {
            AggregateThresholdShareRecipientAuthorityEntry::Complete(qualification) => {
                Ok(inspect(qualification))
            }
            AggregateThresholdShareRecipientAuthorityEntry::Active(_) => {
                Err(AggregateThresholdShareRuntimeError::Runtime(
                    CommonProofRuntimeError::WrongOperationPhase,
                ))
            }
        }
    }

    fn discard(&mut self, handle: u32) -> Result<(), AggregateThresholdShareRuntimeError> {
        self.entries.remove(&handle).map(|_| ()).ok_or(
            AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ),
        )
    }
}

thread_local! {
    static AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY:
        RefCell<AggregateThresholdShareRecipientAuthorityRegistry> =
        RefCell::new(AggregateThresholdShareRecipientAuthorityRegistry::default());
}

fn expected_public_randomness_object_count() -> Result<usize, AggregateThresholdShareRuntimeError> {
    usize::from(FOUNDATION_PROFILE.participant_count)
        .checked_mul(EXPECTED_PUBLIC_RANDOMNESS_OBJECTS_PER_PARTICIPANT)
        .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)
}

fn resolve_verified_public_randomness(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ordered_public_randomness_object_handles: &[u32],
) -> Result<VerifiedPublicRandomness, AggregateThresholdShareRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH
        || ordered_public_randomness_object_handles.len()
            != expected_public_randomness_object_count()?
    {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    let sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        ordered_public_randomness_object_handles,
    )
    .map_err(AggregateThresholdShareRuntimeError::BoardRuntime)?;
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let mut sources = sources.into_iter();
    let setup_intent_sources = sources.by_ref().take(participant_count).collect::<Vec<_>>();
    let commitment_sources = sources.by_ref().take(participant_count).collect::<Vec<_>>();
    let reveal_sources = sources.by_ref().take(participant_count).collect::<Vec<_>>();
    if sources.next().is_some() {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    verify_public_randomness_board_sources(setup_intent_sources, commitment_sources, reveal_sources)
        .map_err(AggregateThresholdShareRuntimeError::Refusal)
}

fn require_dealer_terminals_match_public_randomness(
    verified_public_randomness: &VerifiedPublicRandomness,
    ordered_dealer_terminals: &[VerifiedVssShareLinkageTerminal],
) -> Result<(), AggregateThresholdShareRuntimeError> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let sharing_limb_count = selected_vss_sharing_coordinates()?.len();
    let expected_coefficient_root_count = sharing_limb_count
        .checked_mul(usize::from(FOUNDATION_PROFILE.reconstruction_threshold))
        .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
    let expected_recipient_root_count = sharing_limb_count
        .checked_mul(participant_count)
        .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
    if ordered_dealer_terminals.len() != participant_count {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongTypeOrLength,
        ));
    }
    let context = verified_public_randomness.context();
    for (dealer_roster_position, terminal) in ordered_dealer_terminals.iter().enumerate() {
        let expected_dealer_identity = verified_public_randomness
            .ordered_participant_identities()
            .get(dealer_roster_position)
            .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::WrongTypeOrLength,
            ))?;
        if terminal.protocol_version() != context.protocol_version()
            || terminal.suite_identifier() != context.suite_identifier().into_bytes()
            || terminal.manifest_hash() != context.manifest_hash().into_bytes()
            || terminal.ceremony_context_hash() != context.ceremony_context_hash().into_bytes()
            || terminal.action_context_hash() != context.action_context_hash().into_bytes()
            || terminal.roster_hash() != context.roster_hash().into_bytes()
            || terminal.public_setup_seed()
                != verified_public_randomness.public_setup_seed().into_bytes()
            || terminal.setup_proof_context_hash()
                != verified_public_randomness
                    .setup_proof_context_hash()
                    .into_bytes()
            || usize::from(terminal.roster_position()) != dealer_roster_position
            || terminal.participant_identity() != expected_dealer_identity.into_bytes()
            || terminal.ordered_coefficient_material_roots().len()
                != expected_coefficient_root_count
            || terminal.ordered_recipient_share_material_roots().len()
                != expected_recipient_root_count
            || terminal.ordered_recipient_envelope_hashes().len() != participant_count
        {
            return Err(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
    }
    Ok(())
}

pub(crate) fn require_verified_vss_dealer_terminals_match_public_randomness(
    verified_public_randomness: &VerifiedPublicRandomness,
    ordered_dealer_terminals: &[VerifiedVssShareLinkageTerminal],
) -> Result<(), RefusalReason> {
    require_dealer_terminals_match_public_randomness(
        verified_public_randomness,
        ordered_dealer_terminals,
    )
    .map_err(aggregate_threshold_share_runtime_refusal_reason)
}

pub(crate) fn begin_aggregate_threshold_share_recipient_authority(
    action_randomness_handle: u32,
    local_recipient_roster_position: u16,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ordered_public_randomness_object_handles: &[u32],
    ordered_dealer_terminal_handles: &[u32],
) -> Result<u32, AggregateThresholdShareRuntimeError> {
    if local_recipient_roster_position >= FOUNDATION_PROFILE.participant_count {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    let verified_public_randomness = resolve_verified_public_randomness(
        board_verifier_session_handle,
        board_verifier_session_capability,
        ordered_public_randomness_object_handles,
    )?;
    let local_recipient_identity = *verified_public_randomness
        .ordered_participant_identities()
        .get(usize::from(local_recipient_roster_position))
        .ok_or(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongTypeOrLength,
        ))?;
    let action_private_randomness =
        retain_action_private_randomness_for_exact_family(action_randomness_handle)
            .map_err(AggregateThresholdShareRuntimeError::ActionRandomnessRuntime)?;
    let derivation_input = action_private_randomness.derivation_input();
    let context = verified_public_randomness.context();
    if derivation_input.suite_identifier() != context.suite_identifier()
        || derivation_input.ceremony_context_hash() != context.ceremony_context_hash()
        || derivation_input.action_context_hash() != context.action_context_hash()
        || derivation_input.participant_identity() != local_recipient_identity
    {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    let ordered_dealer_terminals =
        consume_ordered_verified_vss_share_linkage_terminals(ordered_dealer_terminal_handles)?;
    require_dealer_terminals_match_public_randomness(
        &verified_public_randomness,
        &ordered_dealer_terminals,
    )?;

    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let aggregate_share_coefficients = selected_vss_sharing_coordinates()?
        .iter()
        .map(|_| Zeroizing::new(vec![0_u64; POLYNOMIAL_DEGREE]))
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let authority = AggregateThresholdShareRecipientAuthority {
        verified_public_randomness: Some(verified_public_randomness),
        ordered_dealer_terminals: Some(ordered_dealer_terminals),
        local_recipient_identity,
        local_recipient_roster_position,
        action_private_randomness,
        ordered_source_materials_by_dealer: std::iter::repeat_with(|| None)
            .take(participant_count)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        aggregate_share_coefficients: Some(aggregate_share_coefficients),
        generation_material: None,
        ordered_recipient_terminals: std::iter::repeat_with(|| None)
            .take(participant_count)
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        private_vss_mailbox_byte_lengths: None,
    };
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY
        .with(|registry| registry.borrow_mut().retain(authority))
}

/// Positively verifies the complete dealer-major mailbox corpus while the
/// exact dealer terminals are still owned by the recipient authority. The
/// resulting byte-length catalog is development evidence only; omitting it
/// cannot change cryptographic qualification, while requesting exact
/// accounting later fails unless this complete corpus was retained.
pub(crate) fn retain_verified_generated_private_vss_mailbox_corpus_byte_lengths(
    recipient_authority_handle: u32,
    ordered_canonical_signed_envelope_bytes: &[&[u8]],
) -> Result<(), AggregateThresholdShareRuntimeError> {
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let authority = registry.authority_mut(recipient_authority_handle)?;
        if authority.private_vss_mailbox_byte_lengths.is_some() {
            return Err(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::ConsumedState,
            ));
        }
        let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
        )?;
        let ordered_dealer_terminals = authority.ordered_dealer_terminals.as_ref().ok_or(
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
        )?;
        let catalog =
            VerifiedGeneratedPrivateVssMailboxCorpusByteLengthCatalog::from_verified_dealer_terminals(
                verified_public_randomness,
                ordered_dealer_terminals,
                GeneratedPrivateVssMailboxCorpusInput::new(
                    ordered_canonical_signed_envelope_bytes,
                ),
            )?;
        authority.private_vss_mailbox_byte_lengths = Some(catalog);
        Ok(())
    })
}

fn canonical_dealer_vss_statement_bytes(
    verified_public_randomness: &VerifiedPublicRandomness,
    dealer_terminal: &VerifiedVssShareLinkageTerminal,
) -> Result<Vec<u8>, AggregateThresholdShareRuntimeError> {
    let context = verified_public_randomness.context();
    canonical_selected_vss_share_linkage_statement(
        context.protocol_version(),
        context.suite_identifier().into_bytes(),
        context.ceremony_context_hash().into_bytes(),
        context.action_context_hash().into_bytes(),
        context.roster_hash().into_bytes(),
        verified_public_randomness.public_setup_seed().into_bytes(),
        dealer_terminal.participant_identity(),
        dealer_terminal.roster_position(),
        dealer_terminal.ordered_coefficient_material_roots(),
        dealer_terminal.ordered_recipient_share_material_roots(),
    )
    .map_err(|_| AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongTypeOrLength))
}

fn expected_mailbox_material_roots(
    dealer_terminal: &VerifiedVssShareLinkageTerminal,
    recipient_roster_position: u16,
) -> Result<Vec<Hash512>, AggregateThresholdShareRuntimeError> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let sharing_limb_count = selected_vss_sharing_coordinates()?.len();
    let recipient_roster_position = usize::from(recipient_roster_position);
    let mut ordered_roots = Vec::with_capacity(
        dealer_terminal
            .ordered_coefficient_material_roots()
            .len()
            .checked_add(sharing_limb_count)
            .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?,
    );
    ordered_roots.extend(
        dealer_terminal
            .ordered_coefficient_material_roots()
            .iter()
            .copied()
            .map(Hash512::from_bytes),
    );
    for sharing_limb_ordinal in 0..sharing_limb_count {
        let root_ordinal = sharing_limb_ordinal
            .checked_mul(participant_count)
            .and_then(|offset| offset.checked_add(recipient_roster_position))
            .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
        ordered_roots.push(Hash512::from_bytes(
            *dealer_terminal
                .ordered_recipient_share_material_roots()
                .get(root_ordinal)
                .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::WrongTypeOrLength,
                ))?,
        ));
    }
    Ok(ordered_roots)
}

fn require_envelope_matches_dealer_terminal(
    verified_public_randomness: &VerifiedPublicRandomness,
    dealer_terminal: &VerifiedVssShareLinkageTerminal,
    local_recipient_identity: ParticipantIdentity,
    local_recipient_roster_position: u16,
    canonical_signed_envelope_bytes: &[u8],
    authenticated_plaintext_byte_length: usize,
) -> Result<SignedMailboxEnvelope, AggregateThresholdShareRuntimeError> {
    let envelope = SignedMailboxEnvelope::decode(
        canonical_signed_envelope_bytes,
        &CanonicalDecodeLimits::default(),
    )?;
    if envelope.encode()? != canonical_signed_envelope_bytes {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::MalformedEncoding,
        ));
    }
    let context = verified_public_randomness.context();
    let key_schedule_input = &envelope.associated_data.key_schedule_input;
    let dealer_statement_bytes =
        canonical_dealer_vss_statement_bytes(verified_public_randomness, dealer_terminal)?;
    let expected_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        context.protocol_version(),
        context.suite_identifier().into_bytes(),
        crate::foundation::ProofApplicationSlotCeilings::VSS_SHARE_LINKAGE_STATEMENT_SCHEMA_IDENTIFIER,
        &dealer_statement_bytes,
    ));
    let expected_material_roots =
        expected_mailbox_material_roots(dealer_terminal, local_recipient_roster_position)?;
    let expected_envelope_hash = dealer_terminal
        .ordered_recipient_envelope_hashes()
        .get(usize::from(local_recipient_roster_position))
        .copied()
        .ok_or(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongTypeOrLength,
        ))?;
    if key_schedule_input.suite_id != context.suite_identifier()
        || key_schedule_input.ceremony_context_hash != context.ceremony_context_hash()
        || key_schedule_input.action_context_hash != context.action_context_hash()
        || key_schedule_input.roster_hash != context.roster_hash()
        || key_schedule_input.source_participant_id.into_bytes()
            != dealer_terminal.participant_identity()
        || key_schedule_input.recipient_participant_id != local_recipient_identity
        || key_schedule_input.producer_sequence != 0
        || key_schedule_input.statement_hash != expected_statement_hash
        || key_schedule_input.ordered_material_roots != expected_material_roots
        || envelope.envelope_hash()?.into_bytes() != expected_envelope_hash
        || usize::try_from(envelope.ciphertext_descriptor.total_byte_length).ok()
            != Some(authenticated_plaintext_byte_length)
    {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    Ok(envelope)
}

pub(crate) fn require_verified_recipient_vss_mailbox_envelope(
    verified_public_randomness: &VerifiedPublicRandomness,
    dealer_terminal: &VerifiedVssShareLinkageTerminal,
    recipient_identity: ParticipantIdentity,
    recipient_roster_position: u16,
    canonical_signed_envelope_bytes: &[u8],
    authenticated_plaintext_byte_length: usize,
) -> Result<SignedMailboxEnvelope, RefusalReason> {
    require_envelope_matches_dealer_terminal(
        verified_public_randomness,
        dealer_terminal,
        recipient_identity,
        recipient_roster_position,
        canonical_signed_envelope_bytes,
        authenticated_plaintext_byte_length,
    )
    .map_err(aggregate_threshold_share_runtime_refusal_reason)
}

fn aggregate_threshold_share_runtime_refusal_reason(
    error: AggregateThresholdShareRuntimeError,
) -> RefusalReason {
    match error {
        AggregateThresholdShareRuntimeError::Foundation(error) => error.refusal_reason,
        AggregateThresholdShareRuntimeError::Refusal(refusal_reason) => refusal_reason,
        AggregateThresholdShareRuntimeError::RecipientPayload(_) => {
            RefusalReason::MalformedEncoding
        }
        AggregateThresholdShareRuntimeError::InvalidInput => RefusalReason::WrongTypeOrLength,
        AggregateThresholdShareRuntimeError::Profile(_)
        | AggregateThresholdShareRuntimeError::Accounting(_)
        | AggregateThresholdShareRuntimeError::Relation(_)
        | AggregateThresholdShareRuntimeError::RelationCapability(_)
        | AggregateThresholdShareRuntimeError::GenerationPreparation(_)
        | AggregateThresholdShareRuntimeError::Runtime(_)
        | AggregateThresholdShareRuntimeError::ActionRandomnessRuntime(_)
        | AggregateThresholdShareRuntimeError::BoardRuntime(_)
        | AggregateThresholdShareRuntimeError::MailboxRuntime(_) => RefusalReason::WrongContext,
    }
}

const fn aggregate_threshold_share_refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

pub(crate) fn aggregate_threshold_share_runtime_error_status(
    error: AggregateThresholdShareRuntimeError,
) -> u32 {
    match error {
        AggregateThresholdShareRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        AggregateThresholdShareRuntimeError::GenerationPreparation(error) => match error {
            CommonProofGenerationPreparationError::Runtime(error) => {
                super::runtime_ffi::runtime_error_status(error)
            }
            CommonProofGenerationPreparationError::Generation(error) => {
                let _ = error;
                aggregate_threshold_share_refusal_status(RefusalReason::OutsideSupportedProfile)
            }
        },
        AggregateThresholdShareRuntimeError::Foundation(error) => {
            aggregate_threshold_share_refusal_status(error.refusal_reason)
        }
        AggregateThresholdShareRuntimeError::ActionRandomnessRuntime(status)
        | AggregateThresholdShareRuntimeError::BoardRuntime(status)
        | AggregateThresholdShareRuntimeError::MailboxRuntime(status) => status,
        AggregateThresholdShareRuntimeError::Refusal(refusal_reason) => {
            aggregate_threshold_share_refusal_status(refusal_reason)
        }
        AggregateThresholdShareRuntimeError::InvalidInput => {
            aggregate_threshold_share_refusal_status(RefusalReason::WrongTypeOrLength)
        }
        AggregateThresholdShareRuntimeError::RecipientPayload(error) => {
            let refusal_reason = match error {
                RecipientPrivateVssPayloadError::CanonicalEncoding
                | RecipientPrivateVssPayloadError::WrongValue => RefusalReason::MalformedEncoding,
                RecipientPrivateVssPayloadError::WrongSchema => {
                    RefusalReason::UnsupportedVersionOrSuite
                }
                RecipientPrivateVssPayloadError::WrongTypeOrLength => {
                    RefusalReason::WrongTypeOrLength
                }
                RecipientPrivateVssPayloadError::UnsupportedProfile
                | RecipientPrivateVssPayloadError::CountOverflow => {
                    RefusalReason::OutsideSupportedProfile
                }
            };
            aggregate_threshold_share_refusal_status(refusal_reason)
        }
        AggregateThresholdShareRuntimeError::Profile(error) => {
            let _ = error;
            aggregate_threshold_share_refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        AggregateThresholdShareRuntimeError::Accounting(error) => {
            let _ = error;
            aggregate_threshold_share_refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        AggregateThresholdShareRuntimeError::Relation(error) => {
            let _ = error;
            aggregate_threshold_share_refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        AggregateThresholdShareRuntimeError::RelationCapability(error) => {
            let _ = error;
            aggregate_threshold_share_refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

fn reconstruct_dealer_source_materials(
    verified_public_randomness: &VerifiedPublicRandomness,
    dealer_terminal: &VerifiedVssShareLinkageTerminal,
    local_recipient_roster_position: u16,
    authenticated_plaintext_bytes: &[u8],
) -> Result<
    (
        Box<[SetupGeneratedCommittedMaterial]>,
        Box<[super::DecodedRecipientShareLimb]>,
    ),
    AggregateThresholdShareRuntimeError,
> {
    let decoded_payload = decode_recipient_private_vss_payload(authenticated_plaintext_bytes)?;
    if decoded_payload.recipient_roster_position() != local_recipient_roster_position {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    let decoded_limbs = decoded_payload.into_ordered_limbs();
    let sharing_coordinates = selected_vss_sharing_coordinates()?;
    if decoded_limbs.len() != sharing_coordinates.len() {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongTypeOrLength,
        ));
    }
    let profile = selected_committed_material_profile()?;
    let context = verified_public_randomness.context();
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let mut ordered_source_materials = Vec::with_capacity(sharing_coordinates.len());
    for (sharing_limb_ordinal, (decoded_limb, (expected_sharing_limb_index, modulus))) in
        decoded_limbs
            .iter()
            .zip(sharing_coordinates.iter().copied())
            .enumerate()
    {
        if decoded_limb.sharing_limb_index() != expected_sharing_limb_index {
            return Err(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        let material_context_hash = CommittedMaterialContext::new(
            context.suite_identifier().into_bytes(),
            context.ceremony_context_hash().into_bytes(),
            context.action_context_hash().into_bytes(),
            dealer_terminal.participant_identity(),
            CommittedMaterialRole::RecipientShare,
            expected_sharing_limb_index,
            local_recipient_roster_position,
        )
        .context_hash()
        .map_err(|_| {
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::MalformedEncoding)
        })?;
        let (tree, trace_rows) = CommittedMaterialTree::from_canonical_message(
            profile,
            material_context_hash,
            *decoded_limb.recipient_share_material_seed(),
            decoded_limb.canonical_share_coefficients(),
            modulus,
        )
        .map_err(|_| {
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::InvalidArithmeticRelation)
        })?;
        let expected_root_ordinal = sharing_limb_ordinal
            .checked_mul(participant_count)
            .and_then(|offset| offset.checked_add(usize::from(local_recipient_roster_position)))
            .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
        if tree.root()
            != *dealer_terminal
                .ordered_recipient_share_material_roots()
                .get(expected_root_ordinal)
                .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::WrongTypeOrLength,
                ))?
        {
            return Err(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::WrongHashOrRoot,
            ));
        }
        drop(trace_rows);
        ordered_source_materials.push(
            SetupGeneratedCommittedMaterial::from_recomputed_tree_and_canonical_message(
                tree,
                Zeroizing::new(
                    decoded_limb
                        .canonical_share_coefficients()
                        .to_vec()
                        .into_boxed_slice(),
                ),
                modulus,
            )?,
        );
    }
    Ok((ordered_source_materials.into_boxed_slice(), decoded_limbs))
}

#[derive(Clone, Copy)]
enum AggregateSourceShareUpdate {
    Add,
    Remove,
}

fn update_aggregate_with_source_shares(
    aggregate_share_coefficients: &mut [Zeroizing<Vec<u64>>],
    source_limbs: &[super::DecodedRecipientShareLimb],
    update: AggregateSourceShareUpdate,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    let sharing_coordinates = selected_vss_sharing_coordinates()?;
    if aggregate_share_coefficients.len() != sharing_coordinates.len()
        || source_limbs.len() != sharing_coordinates.len()
    {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    if aggregate_share_coefficients
        .iter()
        .zip(source_limbs)
        .zip(sharing_coordinates.iter())
        .any(
            |((aggregate_coefficients, source_limb), (expected_sharing_limb_index, modulus))| {
                source_limb.sharing_limb_index() != *expected_sharing_limb_index
                    || aggregate_coefficients.len() != POLYNOMIAL_DEGREE
                    || source_limb.canonical_share_coefficients().len() != POLYNOMIAL_DEGREE
                    || aggregate_coefficients
                        .iter()
                        .any(|coefficient| *coefficient >= *modulus)
                    || source_limb
                        .canonical_share_coefficients()
                        .iter()
                        .any(|coefficient| *coefficient >= *modulus)
            },
        )
    {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    for ((aggregate_coefficients, source_limb), (_, modulus)) in aggregate_share_coefficients
        .iter_mut()
        .zip(source_limbs)
        .zip(sharing_coordinates.iter().copied())
    {
        let source_coefficients = source_limb.canonical_share_coefficients();
        for (aggregate_coefficient, source_coefficient) in
            aggregate_coefficients.iter_mut().zip(source_coefficients)
        {
            *aggregate_coefficient = match update {
                AggregateSourceShareUpdate::Add => {
                    add_mod_fast(*aggregate_coefficient, *source_coefficient, modulus)
                }
                AggregateSourceShareUpdate::Remove => {
                    sub_mod_fast(*aggregate_coefficient, *source_coefficient, modulus)
                }
            };
        }
    }
    Ok(())
}

fn derive_recipient_input_root_from_dealer_terminals(
    verified_public_randomness: &VerifiedPublicRandomness,
    ordered_dealer_terminals: &[VerifiedVssShareLinkageTerminal],
    recipient_roster_position: u16,
) -> Result<Hash512, AggregateThresholdShareRuntimeError> {
    let ordered_dealer_object_hashes = ordered_dealer_terminals
        .iter()
        .map(|terminal| Hash512::from_bytes(terminal.board_object_hash()))
        .collect::<Vec<_>>();
    let ordered_recipient_envelope_hashes = ordered_dealer_terminals
        .iter()
        .map(|terminal| {
            terminal
                .ordered_recipient_envelope_hashes()
                .get(usize::from(recipient_roster_position))
                .copied()
                .map(Hash512::from_bytes)
                .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::WrongTypeOrLength,
                ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let recipient_identity = *verified_public_randomness
        .ordered_participant_identities()
        .get(usize::from(recipient_roster_position))
        .ok_or(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongTypeOrLength,
        ))?;
    derive_recipient_input_root(
        verified_public_randomness.context().action_context_hash(),
        recipient_identity,
        &ordered_dealer_object_hashes,
        &ordered_recipient_envelope_hashes,
    )
    .map_err(AggregateThresholdShareRuntimeError::Refusal)
}

fn ordered_source_share_roots_for_recipient(
    ordered_dealer_terminals: &[VerifiedVssShareLinkageTerminal],
    recipient_roster_position: u16,
) -> Result<Vec<[u8; 64]>, AggregateThresholdShareRuntimeError> {
    let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
    let sharing_limb_count = selected_vss_sharing_coordinates()?.len();
    let mut ordered_roots = Vec::with_capacity(
        participant_count
            .checked_mul(sharing_limb_count)
            .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?,
    );
    for dealer_terminal in ordered_dealer_terminals {
        for sharing_limb_ordinal in 0..sharing_limb_count {
            let root_ordinal = sharing_limb_ordinal
                .checked_mul(participant_count)
                .and_then(|offset| offset.checked_add(usize::from(recipient_roster_position)))
                .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
            ordered_roots.push(
                *dealer_terminal
                    .ordered_recipient_share_material_roots()
                    .get(root_ordinal)
                    .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                        RefusalReason::WrongTypeOrLength,
                    ))?,
            );
        }
    }
    Ok(ordered_roots)
}

fn derive_aggregate_generation_material(
    verified_public_randomness: &VerifiedPublicRandomness,
    ordered_dealer_terminals: &[VerifiedVssShareLinkageTerminal],
    local_recipient_identity: ParticipantIdentity,
    local_recipient_roster_position: u16,
    action_private_randomness: &ActionPrivateRandomness,
    aggregate_share_coefficients: &[Zeroizing<Vec<u64>>],
) -> Result<AggregateThresholdShareGenerationMaterial, AggregateThresholdShareRuntimeError> {
    let sharing_coordinates = selected_vss_sharing_coordinates()?;
    if aggregate_share_coefficients.len() != sharing_coordinates.len() {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    let profile = selected_committed_material_profile()?;
    let context = verified_public_randomness.context();
    let randomness_domain =
        PrivateRandomnessDomain::vss_expansion(AGGREGATE_MATERIAL_RANDOMNESS_PURPOSE)?;
    let setup_attempt_identifier = action_private_randomness.setup_attempt_identifier();
    let mut ordered_aggregate_materials = Vec::with_capacity(sharing_coordinates.len());
    for (aggregate_coefficients, (sharing_limb_index, modulus)) in aggregate_share_coefficients
        .iter()
        .zip(sharing_coordinates.iter().copied())
    {
        let material_context_hash = CommittedMaterialContext::new(
            context.suite_identifier().into_bytes(),
            context.ceremony_context_hash().into_bytes(),
            context.action_context_hash().into_bytes(),
            local_recipient_identity.into_bytes(),
            CommittedMaterialRole::AggregateThresholdShare,
            sharing_limb_index,
            local_recipient_roster_position,
        )
        .context_hash()
        .map_err(|_| {
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::MalformedEncoding)
        })?;
        let mut material_seed = Zeroizing::new([0_u8; MATERIAL_SEED_BYTE_LENGTH]);
        action_private_randomness
            .begin_stream(
                randomness_domain,
                Hash512::from_bytes(material_context_hash),
                setup_attempt_identifier,
            )?
            .fill_bytes(material_seed.as_mut())?;
        let (tree, trace_rows) = CommittedMaterialTree::from_canonical_message(
            profile,
            material_context_hash,
            *material_seed,
            aggregate_coefficients,
            modulus,
        )
        .map_err(|_| {
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::InvalidArithmeticRelation)
        })?;
        drop(trace_rows);
        ordered_aggregate_materials.push(
            SetupGeneratedCommittedMaterial::from_recomputed_tree_and_canonical_message(
                tree,
                Zeroizing::new(aggregate_coefficients.to_vec().into_boxed_slice()),
                modulus,
            )?,
        );
    }
    let recipient_input_root = derive_recipient_input_root_from_dealer_terminals(
        verified_public_randomness,
        ordered_dealer_terminals,
        local_recipient_roster_position,
    )?;
    let ordered_source_share_roots = ordered_source_share_roots_for_recipient(
        ordered_dealer_terminals,
        local_recipient_roster_position,
    )?;
    let ordered_aggregate_threshold_roots = ordered_aggregate_materials
        .iter()
        .map(|material| material.compact_source().root())
        .collect::<Vec<_>>();
    let canonical_application_statement_bytes =
        canonical_selected_aggregate_threshold_share_statement(
            context.protocol_version(),
            context.suite_identifier().into_bytes(),
            context.ceremony_context_hash().into_bytes(),
            context.action_context_hash().into_bytes(),
            context.roster_hash().into_bytes(),
            local_recipient_identity.into_bytes(),
            local_recipient_roster_position,
            recipient_input_root.into_bytes(),
            &ordered_source_share_roots,
            &ordered_aggregate_threshold_roots,
        )
        .map_err(|_| {
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongTypeOrLength)
        })?;
    if selected_target_data_prime_coordinates()? != sharing_coordinates {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    Ok(AggregateThresholdShareGenerationMaterial {
        ordered_aggregate_materials: ordered_aggregate_materials.into_boxed_slice(),
        canonical_application_statement_bytes,
        pinned_proof_attempt: None,
    })
}

/// Accepts plaintext only after the mailbox-GCM runtime has consumed a
/// one-shot authenticated-plaintext capability for these exact AAD and
/// plaintext bytes. The public FFI wrapper owns that preceding capability
/// consumption; this crate-private operation cannot be called from the page.
pub(crate) fn absorb_authenticated_recipient_vss_payload(
    recipient_authority_handle: u32,
    authenticated_plaintext_capability_handle: u32,
    canonical_signed_envelope_bytes: &[u8],
    authenticated_plaintext_bytes: &[u8],
) -> Result<(), AggregateThresholdShareRuntimeError> {
    let envelope = SignedMailboxEnvelope::decode(
        canonical_signed_envelope_bytes,
        &CanonicalDecodeLimits::default(),
    )?;
    let canonical_associated_data_bytes = envelope.associated_data.encode()?;
    consume_authenticated_mailbox_plaintext_capability(
        authenticated_plaintext_capability_handle,
        &canonical_associated_data_bytes,
        authenticated_plaintext_bytes,
    )
    .map_err(AggregateThresholdShareRuntimeError::MailboxRuntime)?;
    absorb_joined_recipient_vss_payload(
        recipient_authority_handle,
        canonical_signed_envelope_bytes,
        authenticated_plaintext_bytes,
    )
}

fn absorb_joined_recipient_vss_payload(
    recipient_authority_handle: u32,
    canonical_signed_envelope_bytes: &[u8],
    authenticated_plaintext_bytes: &[u8],
) -> Result<(), AggregateThresholdShareRuntimeError> {
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let authority = registry.authority_mut(recipient_authority_handle)?;
        if authority.generation_material.is_some() {
            return Err(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::ConsumedState,
            ));
        }
        let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
        )?;
        let ordered_dealer_terminals = authority.ordered_dealer_terminals.as_ref().ok_or(
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
        )?;
        let decoded_envelope = SignedMailboxEnvelope::decode(
            canonical_signed_envelope_bytes,
            &CanonicalDecodeLimits::default(),
        )?;
        let source_identity = decoded_envelope
            .associated_data
            .key_schedule_input
            .source_participant_id;
        let dealer_roster_position = verified_public_randomness
            .ordered_participant_identities()
            .iter()
            .position(|identity| *identity == source_identity)
            .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ))?;
        if authority
            .ordered_source_materials_by_dealer
            .get(dealer_roster_position)
            .is_some_and(Option::is_some)
        {
            return Err(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::ConsumedState,
            ));
        }
        let dealer_terminal = ordered_dealer_terminals.get(dealer_roster_position).ok_or(
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongTypeOrLength),
        )?;
        require_envelope_matches_dealer_terminal(
            verified_public_randomness,
            dealer_terminal,
            authority.local_recipient_identity,
            authority.local_recipient_roster_position,
            canonical_signed_envelope_bytes,
            authenticated_plaintext_bytes.len(),
        )?;
        let (source_materials, decoded_limbs) = reconstruct_dealer_source_materials(
            verified_public_randomness,
            dealer_terminal,
            authority.local_recipient_roster_position,
            authenticated_plaintext_bytes,
        )?;
        let completed_source_count = authority
            .ordered_source_materials_by_dealer
            .iter()
            .filter(|source| source.is_some())
            .count();
        let final_source = completed_source_count
            .checked_add(1)
            .is_some_and(|count| count == usize::from(FOUNDATION_PROFILE.participant_count));
        if final_source {
            let mut completed_aggregate = authority.aggregate_share_coefficients.take().ok_or(
                AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
            )?;
            if let Err(error) = update_aggregate_with_source_shares(
                &mut completed_aggregate,
                &decoded_limbs,
                AggregateSourceShareUpdate::Add,
            ) {
                authority.aggregate_share_coefficients = Some(completed_aggregate);
                return Err(error);
            }
            let generation_result = derive_aggregate_generation_material(
                verified_public_randomness,
                ordered_dealer_terminals,
                authority.local_recipient_identity,
                authority.local_recipient_roster_position,
                &authority.action_private_randomness,
                &completed_aggregate,
            );
            match generation_result {
                Ok(generation_material) => {
                    authority.generation_material = Some(generation_material);
                }
                Err(error) => {
                    let rollback_result = update_aggregate_with_source_shares(
                        &mut completed_aggregate,
                        &decoded_limbs,
                        AggregateSourceShareUpdate::Remove,
                    );
                    authority.aggregate_share_coefficients = Some(completed_aggregate);
                    rollback_result?;
                    return Err(error);
                }
            }
        } else {
            update_aggregate_with_source_shares(
                authority.aggregate_share_coefficients.as_mut().ok_or(
                    AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
                )?,
                &decoded_limbs,
                AggregateSourceShareUpdate::Add,
            )?;
        }
        let source_slot = authority
            .ordered_source_materials_by_dealer
            .get_mut(dealer_roster_position)
            .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
        if source_slot.replace(source_materials).is_some() {
            return Err(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::ConsumedState,
            ));
        }
        Ok(())
    })
}

struct SingleActiveAggregateSourceRegistry<Source> {
    active: Option<(u32, Source)>,
    next_handle: u32,
}

impl<Source> Default for SingleActiveAggregateSourceRegistry<Source> {
    fn default() -> Self {
        Self {
            active: None,
            next_handle: 1,
        }
    }
}

impl<Source> SingleActiveAggregateSourceRegistry<Source> {
    fn retain(&mut self, source: Source) -> Result<u32, AggregateThresholdShareRuntimeError> {
        if self.active.is_some() || self.next_handle == 0 {
            return Err(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ));
        }
        let handle = self.next_handle;
        self.next_handle = handle.checked_add(1).filter(|next| *next != 0).ok_or(
            AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ),
        )?;
        self.active = Some((handle, source));
        Ok(handle)
    }

    fn source(&self, handle: u32) -> Result<&Source, AggregateThresholdShareRuntimeError> {
        self.active
            .as_ref()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, source)| source)
            .ok_or(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }

    fn take(&mut self, handle: u32) -> Result<Source, AggregateThresholdShareRuntimeError> {
        self.source(handle)?;
        self.active.take().map(|(_, source)| source).ok_or(
            AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ),
        )
    }

    fn restore(
        &mut self,
        handle: u32,
        source: Source,
    ) -> Result<(), AggregateThresholdShareRuntimeError> {
        if handle == 0 || self.active.is_some() {
            return Err(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ));
        }
        self.active = Some((handle, source));
        Ok(())
    }
}

struct AggregateGenerationBoardBindingSource {
    recipient_authority_handle: u32,
}

thread_local! {
    static AGGREGATE_GENERATION_BOARD_BINDING_SOURCE_REGISTRY:
        RefCell<SingleActiveAggregateSourceRegistry<AggregateGenerationBoardBindingSource>> =
        RefCell::new(SingleActiveAggregateSourceRegistry::default());
}

struct SelectedAggregateProofRuntimePlan {
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
    proof_query_count: u32,
}

fn selected_aggregate_proof_runtime_plan(
    canonical_application_statement_bytes: &[u8],
) -> Result<SelectedAggregateProofRuntimePlan, AggregateThresholdShareRuntimeError> {
    let statement_schema_identifier =
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
    let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or(AggregateThresholdShareRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))?;
    let input = selected_committed_material_relation_plan_input()?;
    let compiled_relation_plan =
        compile_aggregate_threshold_share_relation_plan(&input, &relation_context)?;
    let variant = compiled_relation_plan.select_variant(None, None)?;
    let limits = selected_proof_runtime_limits(
        statement_schema_identifier,
        canonical_application_statement_bytes,
        variant,
    )?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &compiled_relation_plan,
        &relation_context,
        None,
        None,
    )?;
    let proof_query_count = relation_plan.proof_query_count()?;
    Ok(SelectedAggregateProofRuntimePlan {
        relation_plan,
        limits,
        proof_query_count,
    })
}

fn require_selected_suite_matches_recipient_authority(
    selected_suite_handle: u32,
    authority: &AggregateThresholdShareRecipientAuthority,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
    )?;
    let context = verified_public_randomness.context();
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() != context.protocol_version()
            || selected_suite.suite_identifier() != context.suite_identifier().into_bytes()
        {
            return Err(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(AggregateThresholdShareRuntimeError::Runtime)??;
    Ok(())
}

fn resolve_local_setup_intent_source(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
    authority: &AggregateThresholdShareRecipientAuthority,
) -> Result<VerifiedBoardApplicationSource, AggregateThresholdShareRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    let mut sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[setup_intent_object_handle],
    )
    .map_err(AggregateThresholdShareRuntimeError::BoardRuntime)?;
    let source = sources
        .pop()
        .ok_or(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::MissingPrerequisite,
        ))?;
    if !sources.is_empty() {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    source.setup_intent_payload()?;
    let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
    )?;
    let context = verified_public_randomness.context();
    let roster_position = usize::from(authority.local_recipient_roster_position);
    if source.object_type() != FoundationObjectType::SetupIntent
        || source.suite_identifier() != context.suite_identifier()
        || source.manifest_hash() != context.manifest_hash()
        || source.ceremony_context_hash() != context.ceremony_context_hash()
        || source.action_context_hash() != context.action_context_hash()
        || source.roster_hash() != context.roster_hash()
        || source.producer_sequence() != 0
        || source.producer_roster_position() != Some(authority.local_recipient_roster_position)
        || source.producer_participant_identity() != Some(authority.local_recipient_identity)
        || verified_public_randomness
            .ordered_setup_intent_object_hashes()
            .get(roster_position)
            != Some(&source.object_hash())
    {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(source)
}

fn resolve_aggregate_generation_reservation_binding(
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    authority: &AggregateThresholdShareRecipientAuthority,
) -> Result<VerifiedStateReservationRuntimeBinding, AggregateThresholdShareRuntimeError> {
    if state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    let binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(AggregateThresholdShareRuntimeError::BoardRuntime)?;
    let roster_hash = authority
        .verified_public_randomness
        .as_ref()
        .ok_or(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::ConsumedState,
        ))?
        .context()
        .roster_hash();
    let expected_authorization_hash = authority
        .action_private_randomness
        .setup_action_randomness_authorization(roster_hash)?;
    if binding.authorization_hash != expected_authorization_hash {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    Ok(binding)
}

fn require_same_action_randomness_handle(
    action_randomness_handle: u32,
    authority: &AggregateThresholdShareRecipientAuthority,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    let retained = retain_action_private_randomness_for_exact_family(action_randomness_handle)
        .map_err(AggregateThresholdShareRuntimeError::ActionRandomnessRuntime)?;
    if !Rc::ptr_eq(&retained, &authority.action_private_randomness) {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_aggregate_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    setup_intent_source: &VerifiedBoardApplicationSource,
    authority: &AggregateThresholdShareRecipientAuthority,
    runtime_plan: &SelectedAggregateProofRuntimePlan,
    checkpoint_continuation: crate::foundation::AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedActionProofAttemptSource, AggregateThresholdShareRuntimeError> {
    let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
    )?;
    let generation_material = authority.generation_material.as_ref().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::MissingPrerequisite),
    )?;
    let context = verified_public_randomness.context();
    let application_slot = ProofApplicationSlot::new(
        context.suite_identifier(),
        context.ceremony_context_hash(),
        context.action_context_hash(),
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(authority.local_recipient_roster_position),
        None,
        None,
    )?;
    let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        context.protocol_version(),
        context.suite_identifier().into_bytes(),
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        &generation_material.canonical_application_statement_bytes,
    ));
    let proof_byte_length = u64::try_from(runtime_plan.limits.proof_byte_length())
        .map_err(|_| AggregateThresholdShareRuntimeError::InvalidInput)?;
    resolve_prepared_action_proof_attempt_source(
        action_randomness_handle,
        verified_reservation_binding,
        setup_intent_source,
        application_slot,
        application_statement_hash,
        proof_byte_length,
        runtime_plan.proof_query_count,
        checkpoint_continuation,
    )
    .map_err(AggregateThresholdShareRuntimeError::ActionRandomnessRuntime)
}

fn prepare_aggregate_common_generation(
    recipient_authority_handle: u32,
    prepared_attempt: PreparedActionProofAttemptSource,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
) -> Result<PreparedCommonProofGeneration, AggregateThresholdShareRuntimeError> {
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let authority = registry.authority_mut(recipient_authority_handle)?;
        let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
        )?;
        let generation_material = authority.generation_material.as_mut().ok_or(
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::MissingPrerequisite),
        )?;
        let statement_schema_identifier =
            ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER;
        let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
            .ok_or(AggregateThresholdShareRuntimeError::Relation(
                RelationPlanError::InvalidDomain,
            ))?;
        let relation_input = selected_committed_material_relation_plan_input()?;
        let compiled_relation_plan =
            compile_aggregate_threshold_share_relation_plan(&relation_input, &relation_context)?;
        let variant = compiled_relation_plan.select_variant(None, None)?;
        let participant_count = usize::from(FOUNDATION_PROFILE.participant_count);
        let sharing_limb_count = selected_vss_sharing_coordinates()?.len();
        let expected_root_count = sharing_limb_count
            .checked_mul(
                participant_count
                    .checked_add(1)
                    .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?,
            )
            .ok_or(AggregateThresholdShareRuntimeError::InvalidInput)?;
        let mut ordered_sources = Vec::with_capacity(expected_root_count);
        for sharing_limb_ordinal in 0..sharing_limb_count {
            for dealer_ordinal in 0..participant_count {
                let material = authority
                    .ordered_source_materials_by_dealer
                    .get(dealer_ordinal)
                    .and_then(Option::as_ref)
                    .and_then(|materials| materials.get(sharing_limb_ordinal))
                    .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                        RefusalReason::MissingPrerequisite,
                    ))?;
                ordered_sources.push(material.owned_authenticated_source());
            }
            let aggregate_material = generation_material
                .ordered_aggregate_materials
                .get(sharing_limb_ordinal)
                .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::MissingPrerequisite,
                ))?;
            ordered_sources.push(aggregate_material.owned_authenticated_source());
        }
        let mut source_polynomials =
            CommittedMaterialSourcePolynomialAdapter::new_aggregate_threshold_share(
                relation_input,
                &relation_context,
                &compiled_relation_plan,
                verified_public_randomness.context().protocol_version(),
                verified_public_randomness
                    .context()
                    .suite_identifier()
                    .into_bytes(),
                prepared_attempt.application_statement_hash().into_bytes(),
                &relation_plan,
                ordered_sources,
            )
            .map_err(|_| {
                AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::InvalidArithmeticRelation,
                )
            })?;
        let relation_trees = source_polynomials.relation_tree_inputs().map_err(|_| {
            AggregateThresholdShareRuntimeError::Refusal(RefusalReason::InvalidArithmeticRelation)
        })?;
        let persistent_proof_coin_input = PersistentProofCoinInput::new(
            prepared_attempt.application_slot(),
            prepared_attempt.application_statement_hash(),
        )?;
        let mut witness_coin_binding = authority
            .action_private_randomness
            .begin_persistent_proof_witness_coin_binding(&persistent_proof_coin_input)?;
        source_polynomials
            .absorb_canonical_semantic_witness(&mut witness_coin_binding)
            .map_err(|_| {
                AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::InvalidArithmeticRelation,
                )
            })?;
        let witness_bound_attempt = bind_prepared_action_proof_attempt_to_canonical_witness(
            prepared_attempt,
            witness_coin_binding,
        )?;
        let pinned_attempt = PinnedAggregateProofAttempt {
            attempt_identifier: witness_bound_attempt.attempt_identifier(),
            application_slot_hash: witness_bound_attempt.application_slot_hash().into_bytes(),
            application_statement_hash: witness_bound_attempt
                .application_statement_hash()
                .into_bytes(),
        };
        if let Some(existing) = &generation_material.pinned_proof_attempt {
            if existing.attempt_identifier != pinned_attempt.attempt_identifier
                || existing.application_slot_hash != pinned_attempt.application_slot_hash
                || existing.application_statement_hash != pinned_attempt.application_statement_hash
            {
                return Err(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::ConsumedState,
                ));
            }
        } else {
            generation_material.pinned_proof_attempt = Some(pinned_attempt);
        }
        let authorization =
            CommonProofGenerationAuthorization::from_witness_bound_authenticated_attempt(
                witness_bound_attempt,
                &relation_plan,
                verified_public_randomness.context().protocol_version(),
                &generation_material.canonical_application_statement_bytes,
                limits,
            )?;
        let attempt_identifier = witness_bound_attempt.private_randomness_attempt_identifier();
        let coordinate_capacity =
            CommonProofPrivateCoinCoordinateCapacity::from_relation_plan_variant(variant).map_err(
                |_| {
                    AggregateThresholdShareRuntimeError::Refusal(
                        RefusalReason::OutsideSupportedProfile,
                    )
                },
            )?;
        let private_coins = PrivateRandomnessCommonProofCoinSource::new(
            Rc::clone(&authority.action_private_randomness),
            statement_schema_identifier,
            Hash512::from_bytes(authorization.binding_hash()),
            attempt_identifier,
            coordinate_capacity,
        )
        .map_err(|_| AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongContext))?;
        PreparedCommonProofGeneration::from_exact_family_sources(
            authorization,
            relation_plan,
            generation_material
                .canonical_application_statement_bytes
                .clone(),
            relation_trees,
            limits,
            CommonProofGenerationSources::new(private_coins, source_polynomials),
        )
        .map_err(AggregateThresholdShareRuntimeError::GenerationPreparation)
    })
}

fn resumed_aggregate_generation_preparation_error(
    error: AggregateThresholdShareRuntimeError,
) -> CommonProofGenerationPreparationError {
    match error {
        AggregateThresholdShareRuntimeError::Runtime(error) => {
            CommonProofGenerationPreparationError::Runtime(error)
        }
        AggregateThresholdShareRuntimeError::GenerationPreparation(error) => error,
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState) => {
            CommonProofGenerationPreparationError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            )
        }
        _ => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding,
        ),
    }
}

#[derive(Clone, Copy)]
pub(crate) enum AggregateThresholdShareGenerationMode {
    Fresh,
    Resume,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_aggregate_threshold_share_generation(
    selected_suite_handle: u32,
    recipient_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: AggregateThresholdShareGenerationMode,
) -> Result<(u32, u32), AggregateThresholdShareRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    let (setup_intent_source, verified_reservation_binding, canonical_application_statement_bytes) =
        AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let authority = registry.authority(recipient_authority_handle)?;
            require_selected_suite_matches_recipient_authority(selected_suite_handle, authority)?;
            require_same_action_randomness_handle(action_randomness_handle, authority)?;
            let setup_intent_source = resolve_local_setup_intent_source(
                board_verifier_session_handle,
                board_verifier_session_capability,
                setup_intent_object_handle,
                authority,
            )?;
            let verified_reservation_binding = resolve_aggregate_generation_reservation_binding(
                state_verifier_session_handle,
                state_verifier_session_capability,
                verified_reservation_handle,
                authority,
            )?;
            let canonical_application_statement_bytes = authority
                .generation_material
                .as_ref()
                .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::MissingPrerequisite,
                ))?
                .canonical_application_statement_bytes
                .clone();
            Ok::<_, AggregateThresholdShareRuntimeError>((
                setup_intent_source,
                verified_reservation_binding,
                canonical_application_statement_bytes,
            ))
        })?;
    let runtime_plan =
        selected_aggregate_proof_runtime_plan(&canonical_application_statement_bytes)?;
    let checkpoint_schedule_digest = runtime_plan
        .relation_plan
        .checkpoint_schedule_digest(runtime_plan.limits)?;
    let fresh_continuation =
        crate::foundation::AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let fresh_prepared_attempt =
        AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let authority = registry.authority(recipient_authority_handle)?;
            resolve_aggregate_prepared_attempt(
                action_randomness_handle,
                verified_reservation_binding,
                &setup_intent_source,
                authority,
                &runtime_plan,
                fresh_continuation,
            )
        })?;
    let generation_family_adapter = match generation_mode {
        AggregateThresholdShareGenerationMode::Fresh => {
            let prepared_generation = prepare_aggregate_common_generation(
                recipient_authority_handle,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?;
            CommonProofGenerationFamilyAdapter::fresh(prepared_generation)
        }
        AggregateThresholdShareGenerationMode::Resume => {
            let fresh_preparation = prepare_aggregate_common_generation(
                recipient_authority_handle,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
                fresh_preparation.runtime_binding_hash(),
                fresh_preparation.generation_authorization_hash(),
                fresh_preparation.proof_attempt_lineage_identifier(),
            );
            drop(fresh_preparation);
            CommonProofGenerationFamilyAdapter::resume(
                description,
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
                Box::new(move |authenticated_continuation| {
                    let resumed_runtime_plan = selected_aggregate_proof_runtime_plan(
                        &canonical_application_statement_bytes,
                    )
                    .map_err(resumed_aggregate_generation_preparation_error)?;
                    let prepared_attempt = AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY
                        .with(|registry| {
                        let registry = registry.borrow();
                        let authority = registry
                            .authority(recipient_authority_handle)
                            .map_err(resumed_aggregate_generation_preparation_error)?;
                        resolve_aggregate_prepared_attempt(
                            action_randomness_handle,
                            verified_reservation_binding,
                            &setup_intent_source,
                            authority,
                            &resumed_runtime_plan,
                            authenticated_continuation,
                        )
                        .map_err(resumed_aggregate_generation_preparation_error)
                    })?;
                    prepare_aggregate_common_generation(
                        recipient_authority_handle,
                        prepared_attempt,
                        resumed_runtime_plan.relation_plan,
                        resumed_runtime_plan.limits,
                    )
                    .map_err(resumed_aggregate_generation_preparation_error)
                }),
            )
        }
    };
    let board_binding_source_handle =
        AGGREGATE_GENERATION_BOARD_BINDING_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .retain(AggregateGenerationBoardBindingSource {
                    recipient_authority_handle,
                })
        })?;
    match retain_common_proof_generation_family_adapter(generation_family_adapter) {
        Ok(adapter_handle) => Ok((adapter_handle, board_binding_source_handle)),
        Err(error) => {
            AGGREGATE_GENERATION_BOARD_BINDING_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(board_binding_source_handle))?;
            Err(AggregateThresholdShareRuntimeError::Runtime(error))
        }
    }
}

fn require_board_source_matches_public_randomness(
    board_source: &VerifiedBoardApplicationSource,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    let context = verified_public_randomness.context();
    if board_source.suite_identifier() != context.suite_identifier()
        || board_source.manifest_hash() != context.manifest_hash()
        || board_source.ceremony_context_hash() != context.ceremony_context_hash()
        || board_source.action_context_hash() != context.action_context_hash()
        || board_source.roster_hash() != context.roster_hash()
    {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_private_share_acceptance_source(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    private_share_acceptance_object_handle: u32,
    verified_public_randomness: &VerifiedPublicRandomness,
) -> Result<VerifiedBoardApplicationSource, AggregateThresholdShareRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    let mut sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[private_share_acceptance_object_handle],
    )
    .map_err(AggregateThresholdShareRuntimeError::BoardRuntime)?;
    let source = sources
        .pop()
        .ok_or(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::MissingPrerequisite,
        ))?;
    if !sources.is_empty() {
        return Err(AggregateThresholdShareRuntimeError::InvalidInput);
    }
    require_board_source_matches_public_randomness(&source, verified_public_randomness)?;
    let payload = source.private_share_acceptance_payload()?;
    let recipient_roster_position =
        source
            .producer_roster_position()
            .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ))?;
    let recipient_identity = source.producer_participant_identity().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongContext),
    )?;
    if source.object_type() != FoundationObjectType::PrivateShareAcceptance
        || source.producer_sequence() != 0
        || payload.aggregate_threshold_share_material_roots().len()
            != selected_vss_sharing_coordinates()?.len()
        || verified_public_randomness
            .ordered_participant_identities()
            .get(usize::from(recipient_roster_position))
            != Some(&recipient_identity)
    {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(source)
}

fn canonical_aggregate_statement_for_acceptance(
    authority: &AggregateThresholdShareRecipientAuthority,
    board_source: &VerifiedBoardApplicationSource,
) -> Result<Vec<u8>, AggregateThresholdShareRuntimeError> {
    let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
    )?;
    require_board_source_matches_public_randomness(board_source, verified_public_randomness)?;
    let payload = board_source.private_share_acceptance_payload()?;
    let recipient_roster_position = board_source.producer_roster_position().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongContext),
    )?;
    let recipient_identity = board_source.producer_participant_identity().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongContext),
    )?;
    if board_source.object_type() != FoundationObjectType::PrivateShareAcceptance
        || board_source.producer_sequence() != 0
        || payload.aggregate_threshold_share_material_roots().len()
            != selected_vss_sharing_coordinates()?.len()
        || verified_public_randomness
            .ordered_participant_identities()
            .get(usize::from(recipient_roster_position))
            != Some(&recipient_identity)
    {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    let ordered_dealer_terminals = authority.ordered_dealer_terminals.as_ref().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
    )?;
    let recipient_input_root = derive_recipient_input_root_from_dealer_terminals(
        verified_public_randomness,
        ordered_dealer_terminals,
        recipient_roster_position,
    )?;
    if payload.recipient_input_root() != recipient_input_root {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    let ordered_source_share_roots = ordered_source_share_roots_for_recipient(
        ordered_dealer_terminals,
        recipient_roster_position,
    )?;
    let ordered_aggregate_threshold_roots = payload
        .aggregate_threshold_share_material_roots()
        .iter()
        .map(|root| root.into_bytes())
        .collect::<Vec<_>>();
    let context = verified_public_randomness.context();
    canonical_selected_aggregate_threshold_share_statement(
        context.protocol_version(),
        context.suite_identifier().into_bytes(),
        context.ceremony_context_hash().into_bytes(),
        context.action_context_hash().into_bytes(),
        context.roster_hash().into_bytes(),
        recipient_identity.into_bytes(),
        recipient_roster_position,
        recipient_input_root.into_bytes(),
        &ordered_source_share_roots,
        &ordered_aggregate_threshold_roots,
    )
    .map_err(|_| AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongTypeOrLength))
}

pub(crate) fn bind_generated_aggregate_threshold_share_proof_to_board(
    generated_common_proof_handle: u32,
    board_binding_source_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    private_share_acceptance_object_handle: u32,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    let recipient_authority_handle =
        AGGREGATE_GENERATION_BOARD_BINDING_SOURCE_REGISTRY.with(|registry| {
            Ok::<_, AggregateThresholdShareRuntimeError>(
                registry
                    .borrow()
                    .source(board_binding_source_handle)?
                    .recipient_authority_handle,
            )
        })?;
    let (board_source, canonical_application_statement_bytes) =
        AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let authority = registry.authority(recipient_authority_handle)?;
            let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
                AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
            )?;
            let board_source = resolve_private_share_acceptance_source(
                board_verifier_session_handle,
                board_verifier_session_capability,
                private_share_acceptance_object_handle,
                verified_public_randomness,
            )?;
            if board_source.producer_roster_position()
                != Some(authority.local_recipient_roster_position)
                || board_source.producer_participant_identity()
                    != Some(authority.local_recipient_identity)
            {
                return Err(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::WrongContext,
                ));
            }
            let canonical_application_statement_bytes =
                canonical_aggregate_statement_for_acceptance(authority, &board_source)?;
            let generated_statement = &authority
                .generation_material
                .as_ref()
                .ok_or(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::MissingPrerequisite,
                ))?
                .canonical_application_statement_bytes;
            if &canonical_application_statement_bytes != generated_statement {
                return Err(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::WrongHashOrRoot,
                ));
            }
            Ok::<_, AggregateThresholdShareRuntimeError>((
                board_source,
                canonical_application_statement_bytes,
            ))
        })?;
    let private_share_acceptance_payload = board_source.private_share_acceptance_payload()?;
    let proof_descriptor = private_share_acceptance_payload.aggregate_threshold_share_proof();
    bind_generated_common_proof_to_verified_board_source(
        generated_common_proof_handle,
        &board_source,
        proof_descriptor,
        &canonical_application_statement_bytes,
    )?;
    AGGREGATE_GENERATION_BOARD_BINDING_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(board_binding_source_handle))?;
    Ok(())
}

struct AggregateVerificationTerminalSource {
    recipient_authority_handle: u32,
    canonical_application_statement_bytes: Vec<u8>,
    board_source: VerifiedBoardApplicationSource,
}

thread_local! {
    static AGGREGATE_VERIFICATION_TERMINAL_SOURCE_REGISTRY:
        RefCell<SingleActiveAggregateSourceRegistry<AggregateVerificationTerminalSource>> =
        RefCell::new(SingleActiveAggregateSourceRegistry::default());
}

pub(crate) fn prepare_aggregate_threshold_share_verification(
    selected_suite_handle: u32,
    recipient_authority_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    private_share_acceptance_object_handle: u32,
) -> Result<(u32, u32), AggregateThresholdShareRuntimeError> {
    let (board_source, canonical_application_statement_bytes) =
        AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let authority = registry.authority(recipient_authority_handle)?;
            require_selected_suite_matches_recipient_authority(selected_suite_handle, authority)?;
            let verified_public_randomness = authority.verified_public_randomness.as_ref().ok_or(
                AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
            )?;
            let board_source = resolve_private_share_acceptance_source(
                board_verifier_session_handle,
                board_verifier_session_capability,
                private_share_acceptance_object_handle,
                verified_public_randomness,
            )?;
            let recipient_roster_position = board_source.producer_roster_position().ok_or(
                AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongContext),
            )?;
            if authority
                .ordered_recipient_terminals
                .get(usize::from(recipient_roster_position))
                .is_none_or(Option::is_some)
            {
                return Err(AggregateThresholdShareRuntimeError::Refusal(
                    RefusalReason::ConsumedState,
                ));
            }
            let canonical_application_statement_bytes =
                canonical_aggregate_statement_for_acceptance(authority, &board_source)?;
            Ok::<_, AggregateThresholdShareRuntimeError>((
                board_source,
                canonical_application_statement_bytes,
            ))
        })?;
    let recipient_roster_position = board_source.producer_roster_position().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::WrongContext),
    )?;
    let verified_board_source = board_source;
    let application_slot = ProofApplicationSlot::new(
        verified_board_source.suite_identifier(),
        verified_board_source.ceremony_context_hash(),
        verified_board_source.action_context_hash(),
        ProofApplicationSlotCeilings::AGGREGATE_THRESHOLD_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        Some(recipient_roster_position),
        None,
        None,
    )?;
    let proof_header = ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.clone(),
        &CanonicalDecodeLimits::default(),
    )?;
    let proof_header_hash = proof_header.proof_header_hash()?;
    let proof_descriptor = verified_board_source
        .private_share_acceptance_payload()?
        .aggregate_threshold_share_proof()
        .clone();
    let proof_application_binding =
        ProofApplicationBinding::new(application_slot, proof_header_hash, proof_descriptor)?;
    let runtime_plan =
        selected_aggregate_proof_runtime_plan(&canonical_application_statement_bytes)?;
    let statement_source =
        super::VerifiedCommonProofStatementSource::from_exact_family_verified_board_source(
            verified_board_source.clone(),
            FOUNDATION_PROFILE.protocol_version,
            canonical_application_statement_bytes.clone(),
            proof_application_binding,
            runtime_plan.relation_plan,
            runtime_plan.limits,
        )?;
    let terminal_source_handle =
        AGGREGATE_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .retain(AggregateVerificationTerminalSource {
                    recipient_authority_handle,
                    canonical_application_statement_bytes,
                    board_source: verified_board_source,
                })
        })?;
    let selected_suite_handle =
        CommonProofSelectedSuiteCapabilityHandle::from_identifier(selected_suite_handle);
    let adapter_result =
        retain_common_proof_verification_family_adapter_from_upstream(move |upstream_inputs| {
            upstream_inputs.prepare_proof_created_tree_family_verification_without_evaluator(
                &selected_suite_handle,
                statement_source,
            )
        });
    match adapter_result {
        Ok(adapter_handle) => Ok((adapter_handle, terminal_source_handle)),
        Err(error) => {
            AGGREGATE_VERIFICATION_TERMINAL_SOURCE_REGISTRY
                .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
            Err(AggregateThresholdShareRuntimeError::Runtime(error))
        }
    }
}

impl AggregateVerificationTerminalSource {
    fn consume_verified_common_proof(
        self,
        verified_common_proof: ConsumedVerifiedCommonProofCapability,
    ) -> Result<(u32, VerifiedAggregateThresholdShareTerminal), CommonProofRuntimeError> {
        let Self {
            recipient_authority_handle,
            canonical_application_statement_bytes,
            board_source,
        } = self;
        let terminal = AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            let authority = registry
                .authority(recipient_authority_handle)
                .map_err(|_| CommonProofRuntimeError::UnknownOrStaleHandle)?;
            let verified_public_randomness = authority
                .verified_public_randomness
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            VerifiedAggregateThresholdShareTerminal::from_consumed_common_proof(
                verified_common_proof,
                &canonical_application_statement_bytes,
                board_source,
                verified_public_randomness,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        })?;
        Ok((recipient_authority_handle, terminal))
    }
}

fn complete_vss_qualification_if_ready(
    recipient_authority_handle: u32,
) -> Result<bool, AggregateThresholdShareRuntimeError> {
    let ready = AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let authority = registry.authority(recipient_authority_handle)?;
        Ok::<_, AggregateThresholdShareRuntimeError>(
            authority
                .ordered_recipient_terminals
                .iter()
                .all(Option::is_some),
        )
    })?;
    if !ready {
        return Ok(false);
    }
    let mut authority =
        AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
            registry
                .borrow_mut()
                .take_active(recipient_authority_handle)
        })?;
    let public_randomness = authority.verified_public_randomness.take().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
    )?;
    let ordered_dealer_terminals = authority.ordered_dealer_terminals.take().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::ConsumedState),
    )?;
    let ordered_recipient_terminals = authority
        .ordered_recipient_terminals
        .into_vec()
        .into_iter()
        .map(|terminal| {
            terminal.ok_or(AggregateThresholdShareRuntimeError::Refusal(
                RefusalReason::MissingPrerequisite,
            ))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let generation_material = authority.generation_material.take().ok_or(
        AggregateThresholdShareRuntimeError::Refusal(RefusalReason::MissingPrerequisite),
    )?;
    let selected_target_coordinates = selected_target_data_prime_coordinates()?;
    let selected_sharing_coordinates = selected_vss_sharing_coordinates()?;
    if selected_target_coordinates != selected_sharing_coordinates
        || generation_material.ordered_aggregate_materials.len()
            != selected_target_coordinates.len()
    {
        return Err(AggregateThresholdShareRuntimeError::Refusal(
            RefusalReason::WrongTypeOrLength,
        ));
    }
    let local_target_release_limbs = generation_material
        .ordered_aggregate_materials
        .into_vec()
        .into_iter()
        .zip(selected_target_coordinates.iter().copied())
        .map(|(committed_share, (data_modulus_index, _))| {
            BrowserOwnedAggregateThresholdShareLimb::from_proof_generation_source(
                data_modulus_index,
                committed_share,
            )
        })
        .collect::<Vec<_>>();
    let qualification = VerifiedAcceptedSetupVssQualification::from_verified_terminals(
        public_randomness,
        ordered_dealer_terminals,
        ordered_recipient_terminals,
        local_target_release_limbs,
        authority.private_vss_mailbox_byte_lengths.take(),
    )?;
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .complete(recipient_authority_handle, qualification)
    })?;
    Ok(true)
}

pub(crate) fn finish_aggregate_threshold_share_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<bool, AggregateThresholdShareRuntimeError> {
    let terminal_source = AGGREGATE_VERIFICATION_TERMINAL_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
    let terminal_source_cell = RefCell::new(Some(terminal_source));
    let insertion_result = super::consume_verified_common_proof_with_family_terminal(
        &super::VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_common_proof| {
            let terminal_source = terminal_source_cell
                .borrow_mut()
                .take()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            let (recipient_authority_handle, terminal) =
                terminal_source.consume_verified_common_proof(verified_common_proof)?;
            AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
                let mut registry = registry.borrow_mut();
                let authority = registry
                    .authority_mut(recipient_authority_handle)
                    .map_err(|_| CommonProofRuntimeError::UnknownOrStaleHandle)?;
                let recipient_roster_position = usize::from(terminal.roster_position());
                let slot = authority
                    .ordered_recipient_terminals
                    .get_mut(recipient_roster_position)
                    .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
                if slot.replace(terminal).is_some() {
                    return Err(CommonProofRuntimeError::WrongOperationPhase);
                }
                Ok(recipient_authority_handle)
            })
        },
    );
    let recipient_authority_handle = match insertion_result {
        Ok(handle) => handle,
        Err(error) => {
            if let Some(terminal_source) = terminal_source_cell.into_inner() {
                AGGREGATE_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
                    registry
                        .borrow_mut()
                        .restore(terminal_source_handle, terminal_source)
                })?;
            }
            return Err(AggregateThresholdShareRuntimeError::Runtime(error));
        }
    };
    complete_vss_qualification_if_ready(recipient_authority_handle)
}

pub(crate) fn consume_verified_accepted_setup_vss_qualification(
    recipient_authority_handle: u32,
) -> Result<VerifiedAcceptedSetupVssQualification, AggregateThresholdShareRuntimeError> {
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .consume_complete(recipient_authority_handle)
    })
}

pub(crate) fn restore_verified_accepted_setup_vss_qualification(
    recipient_authority_handle: u32,
    qualification: VerifiedAcceptedSetupVssQualification,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .complete(recipient_authority_handle, qualification)
    })
}

pub(crate) fn with_verified_accepted_setup_vss_public_randomness<Output>(
    recipient_authority_handle: u32,
    inspect: impl FnOnce(
        &VerifiedPublicRandomness,
    ) -> Result<Output, AggregateThresholdShareRuntimeError>,
) -> Result<Output, AggregateThresholdShareRuntimeError> {
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .borrow()
            .with_complete(recipient_authority_handle, |qualification| {
                inspect(qualification.verified_public_randomness())
            })?
    })
}

/// Borrows the verifier-owned object-hash sources needed to construct the
/// canonical accepted-setup package. Neither hash list can be supplied or
/// replaced by the host: all five lists remain rooted in the completed VSS
/// authority.
pub(crate) fn with_verified_accepted_setup_vss_package_sources<Output>(
    recipient_authority_handle: u32,
    inspect: impl FnOnce(
        &VerifiedPublicRandomness,
        &VerifiedVssQualificationTerminals,
    ) -> Result<Output, AggregateThresholdShareRuntimeError>,
) -> Result<Output, AggregateThresholdShareRuntimeError> {
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY.with(|registry| {
        registry
            .borrow()
            .with_complete(recipient_authority_handle, |qualification| {
                inspect(
                    qualification.verified_public_randomness(),
                    qualification.qualification_terminals(),
                )
            })?
    })
}

pub(crate) fn discard_aggregate_threshold_share_generation_board_binding_source(
    board_binding_source_handle: u32,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    AGGREGATE_GENERATION_BOARD_BINDING_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(board_binding_source_handle)
            .map(|_| ())
    })
}

pub(crate) fn discard_aggregate_threshold_share_verification_terminal_source(
    terminal_source_handle: u32,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    AGGREGATE_VERIFICATION_TERMINAL_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(terminal_source_handle)
            .map(|_| ())
    })
}

pub(crate) fn discard_aggregate_threshold_share_recipient_authority(
    recipient_authority_handle: u32,
) -> Result<(), AggregateThresholdShareRuntimeError> {
    AGGREGATE_THRESHOLD_SHARE_RECIPIENT_AUTHORITY_REGISTRY
        .with(|registry| registry.borrow_mut().discard(recipient_authority_handle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_share_canonical_coefficients_have_one_retained_owner_after_generation() {
        let accounting = aggregate_threshold_share_canonical_coefficient_memory_accounting()
            .expect("selected aggregate-share coefficient accounting");

        assert_eq!(
            accounting.retained_before_final_source_byte_length(),
            3_145_728
        );
        assert_eq!(accounting.maximum_transient_byte_length(), 6_291_456);
        assert_eq!(
            accounting.retained_after_final_source_byte_length(),
            3_145_728
        );
        assert_eq!(
            accounting.removed_generation_duplicate_byte_length(),
            6_291_456
        );
        assert_eq!(accounting.retained_target_release_byte_length(), 3_145_728);
        assert_eq!(
            accounting.removed_persistent_duplicate_byte_length(),
            3_145_728
        );
        let sharing_limb_count = u64::try_from(
            selected_vss_sharing_coordinates()
                .expect("selected sharing coordinates")
                .len(),
        )
        .expect("selected sharing limb count fits u64");
        assert_eq!(
            accounting.retained_before_final_source_byte_length(),
            sharing_limb_count
                * u64::try_from(POLYNOMIAL_DEGREE).expect("polynomial degree fits u64")
                * u64::try_from(size_of::<u64>()).expect("coefficient width fits u64")
        );
    }

    #[test]
    fn single_active_source_registry_is_bounded_one_shot_and_restorable_before_consumption() {
        let mut registry = SingleActiveAggregateSourceRegistry::default();
        let handle = registry.retain(41_u32).expect("first source retained");
        assert!(matches!(
            registry.retain(42),
            Err(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ))
        ));
        assert_eq!(*registry.source(handle).expect("source remains live"), 41);

        let source = registry.take(handle).expect("source consumed once");
        assert!(matches!(
            registry.take(handle),
            Err(AggregateThresholdShareRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
        ));
        registry
            .restore(handle, source)
            .expect("pre-consumption downstream failure restores the exact source");
        assert_eq!(registry.take(handle).expect("restored source consumed"), 41);
    }

    #[test]
    fn ffi_status_mapping_preserves_refusals_and_classifies_payload_failures() {
        let refusal_status = |reason: RefusalReason| reason.canonical_code() as u32;
        assert_eq!(
            aggregate_threshold_share_runtime_error_status(
                AggregateThresholdShareRuntimeError::InvalidInput,
            ),
            refusal_status(RefusalReason::WrongTypeOrLength),
        );
        assert_eq!(
            aggregate_threshold_share_runtime_error_status(
                AggregateThresholdShareRuntimeError::RecipientPayload(
                    RecipientPrivateVssPayloadError::CanonicalEncoding,
                ),
            ),
            refusal_status(RefusalReason::MalformedEncoding),
        );
        assert_eq!(
            aggregate_threshold_share_runtime_error_status(
                AggregateThresholdShareRuntimeError::RecipientPayload(
                    RecipientPrivateVssPayloadError::WrongSchema,
                ),
            ),
            refusal_status(RefusalReason::UnsupportedVersionOrSuite),
        );
        for payload_error in [
            RecipientPrivateVssPayloadError::UnsupportedProfile,
            RecipientPrivateVssPayloadError::CountOverflow,
        ] {
            assert_eq!(
                aggregate_threshold_share_runtime_error_status(
                    AggregateThresholdShareRuntimeError::RecipientPayload(payload_error),
                ),
                refusal_status(RefusalReason::OutsideSupportedProfile),
            );
        }
        assert_eq!(
            aggregate_threshold_share_runtime_error_status(
                AggregateThresholdShareRuntimeError::Runtime(
                    CommonProofRuntimeError::UnknownOrStaleHandle,
                ),
            ),
            refusal_status(RefusalReason::ConsumedState),
        );
        assert_eq!(
            aggregate_threshold_share_runtime_error_status(
                AggregateThresholdShareRuntimeError::MailboxRuntime(0xfedc_ba98),
            ),
            0xfedc_ba98,
        );
    }
}
