//! Browser/WASM generation lifecycle for the selected same-secret and public-
//! key-share relations.
//!
//! Canonical statements and every witness source are derived from retained
//! setup-generation authority. JavaScript receives only the generic prover
//! adapter and an opaque retained handle for the statement lifecycle.

use core::slice;
use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    bgv::setup::{
        SetupGenerationAuthorityHandle, SetupGenerationKeyRelationApplication,
        SetupGenerationKeyRelationPreparationSource, SetupKeyRelationGenerationPreparationError,
        SetupKeyRelationProofFamily, add_generated_proof_source_to_accepted_setup_package_builder,
        resolve_setup_generation_key_relation_preparation_source,
        with_setup_generation_key_relation,
    },
    foundation::{
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, CanonicalDecodeLimits, FoundationObjectType,
        FoundationSchemaError, Hash512, ParticipantIdentity, PreparedActionProofAttemptSource,
        ProofApplicationSlot, ProofObjectHeader, RefusalReason,
        STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, VerifiedBoardApplicationSource,
        VerifiedStateReservationRuntimeBinding, resolve_prepared_action_proof_attempt_source,
        resolve_verified_board_application_sources, verified_state_reservation_binding,
    },
};

use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    common_proof_generation_authenticated_transcript_prefix_request,
    preflight_generated_common_proof_attempt_binding,
    preflight_generated_common_proof_pending_statement,
    retain_common_proof_generation_family_adapter, retire_generated_common_proof_capabilities,
    supply_common_proof_generation_authenticated_transcript_prefix,
    with_common_proof_selected_suite,
};
use super::{
    CommonProofGenerationPreparationError, CommonProofRelationPlanCapability,
    CommonProofRelationPlanCapabilityError, CommonProofRuntimeError, CommonProofRuntimeLimits,
    ExactSameSecretAuthenticatedTranscriptPrefixRequest, PreparedExactSameSecretTranscriptPrefix,
    ProofProfileError, RelationPlanError, SelectedApplicationStatementContext,
    SelectedProofAccountingError,
    attach_verified_vss_low_degree_evidence_to_same_secret_generation,
    compile_public_key_share_relation_plan, compile_same_secret_relation_plan,
    decode_selected_public_key_share_statement, decode_selected_same_secret_statement,
    detach_verified_vss_low_degree_evidence_from_same_secret_generation,
    selected_proof_runtime_limits, selected_public_key_share_relation_plan_input,
    selected_relation_plan_check_context, selected_same_secret_relation_plan_input,
    verified_application_statement_hash, with_attached_verified_vss_low_degree_evidence,
};

const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_RETAINED_GENERATION_STATEMENT_SOURCE_COUNT: usize = 16;

#[derive(Debug)]
enum SetupKeyRelationRuntimeError {
    Accounting(SelectedProofAccountingError),
    Profile(ProofProfileError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    Runtime(CommonProofRuntimeError),
    GenerationPreparation(SetupKeyRelationGenerationPreparationError),
    Foundation(FoundationSchemaError),
    ActionRandomnessRuntime(u32),
    BoardRuntime(u32),
    StateRuntime(u32),
    Refusal(RefusalReason),
    InvalidInput,
}

impl From<SelectedProofAccountingError> for SetupKeyRelationRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<ProofProfileError> for SetupKeyRelationRuntimeError {
    fn from(error: ProofProfileError) -> Self {
        Self::Profile(error)
    }
}

impl From<RelationPlanError> for SetupKeyRelationRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for SetupKeyRelationRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<CommonProofRuntimeError> for SetupKeyRelationRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<SetupKeyRelationGenerationPreparationError> for SetupKeyRelationRuntimeError {
    fn from(error: SetupKeyRelationGenerationPreparationError) -> Self {
        Self::GenerationPreparation(error)
    }
}

impl From<FoundationSchemaError> for SetupKeyRelationRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Foundation(error)
    }
}

impl From<RefusalReason> for SetupKeyRelationRuntimeError {
    fn from(error: RefusalReason) -> Self {
        Self::Refusal(error)
    }
}

struct SelectedSetupKeyRelationProofRuntimePlan {
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
}

#[derive(Clone, Copy)]
struct SetupKeyRelationConstructionBinding {
    application_statement_schema_identifier: u16,
    relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    relation_plan_variant_hash: [u8; Hash512::BYTE_LENGTH],
    construction_plan_identity_hash: [u8; Hash512::BYTE_LENGTH],
}

impl SetupKeyRelationConstructionBinding {
    const fn from_relation_plan(relation_plan: &CommonProofRelationPlanCapability) -> Self {
        Self {
            application_statement_schema_identifier: relation_plan
                .application_statement_schema_identifier(),
            relation_plan_hash: relation_plan.relation_plan_hash(),
            relation_plan_variant_hash: relation_plan.relation_plan_variant_hash(),
            construction_plan_identity_hash: relation_plan
                .row_code_whir_construction_plan_identity_hash(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AuthenticatedSetupKeyRelationGenerationStatementSource {
    family: SetupKeyRelationProofFamily,
    protocol_version: u16,
    application_slot: ProofApplicationSlot,
    application_slot_hash: [u8; Hash512::BYTE_LENGTH],
    application_statement_hash: [u8; Hash512::BYTE_LENGTH],
    participant_identity: [u8; Hash512::BYTE_LENGTH],
    source_roots: Box<[[u8; Hash512::BYTE_LENGTH]]>,
    relation_plan_hash: [u8; Hash512::BYTE_LENGTH],
    relation_plan_variant_hash: [u8; Hash512::BYTE_LENGTH],
    construction_plan_identity_hash: [u8; Hash512::BYTE_LENGTH],
    generation_binding_hash: [u8; Hash512::BYTE_LENGTH],
    attempt_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    vss_low_degree_evidence_handle: Option<u32>,
    canonical_application_statement_bytes: Box<[u8]>,
}

enum SetupKeyRelationGenerationStatementSourceState {
    Available(AuthenticatedSetupKeyRelationGenerationStatementSource),
    VerificationReserved(AuthenticatedSetupKeyRelationGenerationStatementSource),
}

struct SetupKeyRelationGenerationStatementSourceRegistry {
    next_handle: u32,
    sources: BTreeMap<u32, SetupKeyRelationGenerationStatementSourceState>,
}

impl Default for SetupKeyRelationGenerationStatementSourceRegistry {
    fn default() -> Self {
        Self {
            next_handle: 1,
            sources: BTreeMap::new(),
        }
    }
}

impl SetupKeyRelationGenerationStatementSourceRegistry {
    fn retain(
        &mut self,
        source: AuthenticatedSetupKeyRelationGenerationStatementSource,
    ) -> Result<u32, CommonProofRuntimeError> {
        if self.sources.len() >= MAXIMUM_RETAINED_GENERATION_STATEMENT_SOURCE_COUNT
            || self.next_handle == 0
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = self.next_handle;
        self.next_handle = handle
            .checked_add(1)
            .filter(|next_handle| *next_handle != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        if self
            .sources
            .insert(
                handle,
                SetupKeyRelationGenerationStatementSourceState::Available(source),
            )
            .is_some()
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        Ok(handle)
    }

    fn available(
        &self,
        handle: u32,
        expected_family: SetupKeyRelationProofFamily,
    ) -> Result<&AuthenticatedSetupKeyRelationGenerationStatementSource, CommonProofRuntimeError>
    {
        match self.sources.get(&handle) {
            Some(SetupKeyRelationGenerationStatementSourceState::Available(source))
                if source.family == expected_family =>
            {
                Ok(source)
            }
            Some(SetupKeyRelationGenerationStatementSourceState::Available(_))
            | Some(SetupKeyRelationGenerationStatementSourceState::VerificationReserved(_)) => {
                Err(CommonProofRuntimeError::WrongOperationPhase)
            }
            None => Err(CommonProofRuntimeError::UnknownOrStaleHandle),
        }
    }

    fn reserved(
        &self,
        handle: u32,
        expected_family: SetupKeyRelationProofFamily,
    ) -> Result<&AuthenticatedSetupKeyRelationGenerationStatementSource, CommonProofRuntimeError>
    {
        match self.sources.get(&handle) {
            Some(SetupKeyRelationGenerationStatementSourceState::VerificationReserved(source))
                if source.family == expected_family =>
            {
                Ok(source)
            }
            Some(SetupKeyRelationGenerationStatementSourceState::Available(_))
            | Some(SetupKeyRelationGenerationStatementSourceState::VerificationReserved(_)) => {
                Err(CommonProofRuntimeError::WrongOperationPhase)
            }
            None => Err(CommonProofRuntimeError::UnknownOrStaleHandle),
        }
    }

    fn reserve_verification(
        &mut self,
        handle: u32,
        expected_family: SetupKeyRelationProofFamily,
    ) -> Result<AuthenticatedSetupKeyRelationGenerationStatementSource, CommonProofRuntimeError>
    {
        let source = self.available(handle, expected_family)?.clone();
        let entry = self
            .sources
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        *entry =
            SetupKeyRelationGenerationStatementSourceState::VerificationReserved(source.clone());
        Ok(source)
    }

    fn restore_verification(
        &mut self,
        handle: u32,
        expected_family: SetupKeyRelationProofFamily,
    ) -> Result<(), CommonProofRuntimeError> {
        let source = self.reserved(handle, expected_family)?.clone();
        let entry = self
            .sources
            .get_mut(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        *entry = SetupKeyRelationGenerationStatementSourceState::Available(source);
        Ok(())
    }

    fn take_available(
        &mut self,
        handle: u32,
        expected_family: SetupKeyRelationProofFamily,
    ) -> Result<AuthenticatedSetupKeyRelationGenerationStatementSource, CommonProofRuntimeError>
    {
        self.available(handle, expected_family)?;
        match self.sources.remove(&handle) {
            Some(SetupKeyRelationGenerationStatementSourceState::Available(source)) => Ok(source),
            _ => unreachable!("an available source changed state without an intervening call"),
        }
    }

    fn take_reserved(
        &mut self,
        handle: u32,
        expected_family: SetupKeyRelationProofFamily,
    ) -> Result<AuthenticatedSetupKeyRelationGenerationStatementSource, CommonProofRuntimeError>
    {
        self.reserved(handle, expected_family)?;
        match self.sources.remove(&handle) {
            Some(SetupKeyRelationGenerationStatementSourceState::VerificationReserved(source)) => {
                Ok(source)
            }
            _ => unreachable!("a reserved source changed state without an intervening call"),
        }
    }

    fn restore_available(
        &mut self,
        handle: u32,
        source: AuthenticatedSetupKeyRelationGenerationStatementSource,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.sources.contains_key(&handle) {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.sources.insert(
            handle,
            SetupKeyRelationGenerationStatementSourceState::Available(source),
        );
        Ok(())
    }

    fn consume_available_with(
        &mut self,
        handle: u32,
        expected_family: SetupKeyRelationProofFamily,
        consume: impl FnOnce(
            &AuthenticatedSetupKeyRelationGenerationStatementSource,
        ) -> Result<(), CommonProofRuntimeError>,
    ) -> Result<(), CommonProofRuntimeError> {
        let source = self.take_available(handle, expected_family)?;
        if let Err(error) = consume(&source) {
            self.restore_available(handle, source)?;
            return Err(error);
        }
        Ok(())
    }
}

thread_local! {
    static SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY:
        RefCell<SetupKeyRelationGenerationStatementSourceRegistry> =
            RefCell::new(SetupKeyRelationGenerationStatementSourceRegistry::default());
}

type DecodedSetupKeyRelationStatementBinding = (
    [u8; Hash512::BYTE_LENGTH],
    u16,
    Vec<[u8; Hash512::BYTE_LENGTH]>,
);

fn decode_authenticated_setup_key_relation_statement_binding(
    family: SetupKeyRelationProofFamily,
    protocol_version: u16,
    suite_identifier: [u8; Hash512::BYTE_LENGTH],
    canonical_application_statement_bytes: &[u8],
) -> Result<DecodedSetupKeyRelationStatementBinding, CommonProofRuntimeError> {
    let statement_context =
        SelectedApplicationStatementContext::new(protocol_version, suite_identifier, None, None);
    match family {
        SetupKeyRelationProofFamily::SameSecret => {
            let statement = decode_selected_same_secret_statement(
                canonical_application_statement_bytes,
                statement_context,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let mut source_roots = statement.ordered_degree_zero_commitment_roots().to_vec();
            source_roots.extend_from_slice(&statement.anchor_commitment_roots());
            Ok((
                statement.participant_identity(),
                statement.roster_position(),
                source_roots,
            ))
        }
        SetupKeyRelationProofFamily::PublicKeyShare => {
            let statement = decode_selected_public_key_share_statement(
                canonical_application_statement_bytes,
                statement_context,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
            let mut source_roots = statement.anchor_commitment_roots().to_vec();
            source_roots.push(statement.public_key_share_root());
            Ok((
                statement.participant_identity(),
                statement.roster_position(),
                source_roots,
            ))
        }
    }
}

impl AuthenticatedSetupKeyRelationGenerationStatementSource {
    fn from_production_authority(
        preparation_source: &SetupGenerationKeyRelationPreparationSource,
        construction_binding: SetupKeyRelationConstructionBinding,
        adapter_description: CommonProofGenerationFamilyAdapterDescription,
        vss_low_degree_evidence_handle: Option<u32>,
    ) -> Result<Self, SetupKeyRelationRuntimeError> {
        let family = preparation_source.family();
        let statement_schema_identifier = family.statement_schema_identifier();
        if adapter_description.application_statement_schema_identifier()
            != statement_schema_identifier
            || adapter_description.common_proof_runtime_binding_hash()
                != adapter_description.common_proof_generation_authorization_hash()
        {
            return Err(SetupKeyRelationRuntimeError::Runtime(
                CommonProofRuntimeError::WrongVerificationBinding,
            ));
        }
        if matches!(
            (family, vss_low_degree_evidence_handle),
            (SetupKeyRelationProofFamily::SameSecret, None)
                | (SetupKeyRelationProofFamily::PublicKeyShare, Some(_))
        ) {
            return Err(SetupKeyRelationRuntimeError::Refusal(
                RefusalReason::MissingPrerequisite,
            ));
        }
        let (participant_identity, roster_position, source_roots) =
            decode_authenticated_setup_key_relation_statement_binding(
                family,
                preparation_source.protocol_version(),
                preparation_source.suite_identifier(),
                preparation_source.canonical_application_statement_bytes(),
            )
            .map_err(|_| SetupKeyRelationRuntimeError::Refusal(RefusalReason::WrongContext))?;
        if participant_identity != preparation_source.participant_identity()
            || roster_position != preparation_source.roster_position()
            || source_roots.is_empty()
            || source_roots.contains(&[0_u8; Hash512::BYTE_LENGTH])
            || construction_binding.application_statement_schema_identifier
                != statement_schema_identifier
        {
            return Err(SetupKeyRelationRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes(preparation_source.suite_identifier()),
            Hash512::from_bytes(preparation_source.ceremony_context_hash()),
            Hash512::from_bytes(preparation_source.action_context_hash()),
            statement_schema_identifier,
            Some(roster_position),
            None,
            None,
        )?;
        let application_slot_hash = application_slot.hash()?.into_bytes();
        let application_statement_hash = verified_application_statement_hash(
            preparation_source.protocol_version(),
            preparation_source.suite_identifier(),
            statement_schema_identifier,
            preparation_source.canonical_application_statement_bytes(),
        );
        Ok(Self {
            family,
            protocol_version: preparation_source.protocol_version(),
            application_slot,
            application_slot_hash,
            application_statement_hash,
            participant_identity,
            source_roots: source_roots.into_boxed_slice(),
            relation_plan_hash: construction_binding.relation_plan_hash,
            relation_plan_variant_hash: construction_binding.relation_plan_variant_hash,
            construction_plan_identity_hash: construction_binding.construction_plan_identity_hash,
            generation_binding_hash: adapter_description
                .common_proof_generation_authorization_hash(),
            attempt_identifier: adapter_description.proof_attempt_lineage_identifier(),
            vss_low_degree_evidence_handle,
            canonical_application_statement_bytes: preparation_source
                .canonical_application_statement_bytes()
                .to_vec()
                .into_boxed_slice(),
        })
    }

    fn validate(&self) -> Result<(), CommonProofRuntimeError> {
        let application_slot_hash = self
            .application_slot
            .hash()
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
            .into_bytes();
        let (participant_identity, roster_position, source_roots) =
            decode_authenticated_setup_key_relation_statement_binding(
                self.family,
                self.protocol_version,
                self.application_slot.suite_identifier().into_bytes(),
                &self.canonical_application_statement_bytes,
            )?;
        if self.protocol_version == 0
            || self.application_slot_hash != application_slot_hash
            || self
                .application_slot
                .application_statement_schema_identifier()
                != self.family.statement_schema_identifier()
            || self.application_slot.roster_position() != Some(self.roster_position())
            || self.application_slot.schedule_position().is_some()
            || self.application_slot.producer_sequence().is_some()
            || self.participant_identity != participant_identity
            || self.roster_position() != roster_position
            || self.source_roots.is_empty()
            || self.source_roots.as_ref() != source_roots.as_slice()
            || self.source_roots.contains(&[0_u8; Hash512::BYTE_LENGTH])
            || self.generation_binding_hash == [0_u8; Hash512::BYTE_LENGTH]
            || self.attempt_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]
            || matches!(
                (self.family, self.vss_low_degree_evidence_handle),
                (SetupKeyRelationProofFamily::SameSecret, None)
                    | (SetupKeyRelationProofFamily::PublicKeyShare, Some(_))
            )
            || verified_application_statement_hash(
                self.protocol_version,
                self.application_slot.suite_identifier().into_bytes(),
                self.family.statement_schema_identifier(),
                &self.canonical_application_statement_bytes,
            ) != self.application_statement_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let current_plan = selected_setup_key_relation_proof_runtime_plan(
            self.family,
            &self.canonical_application_statement_bytes,
        )
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        if current_plan.relation_plan.relation_plan_hash() != self.relation_plan_hash
            || current_plan.relation_plan.relation_plan_variant_hash()
                != self.relation_plan_variant_hash
            || current_plan
                .relation_plan
                .row_code_whir_construction_plan_identity_hash()
                != self.construction_plan_identity_hash
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(())
    }

    pub(crate) const fn roster_position(&self) -> u16 {
        self.application_slot
            .roster_position()
            .expect("setup key-relation source slots always carry a roster position")
    }

    pub(crate) fn canonical_application_statement_bytes(&self) -> &[u8] {
        &self.canonical_application_statement_bytes
    }

    pub(crate) fn same_secret_low_degree_evidence_binding(
        &self,
    ) -> Result<(u32, [u8; Hash512::BYTE_LENGTH]), CommonProofRuntimeError> {
        if self.family != SetupKeyRelationProofFamily::SameSecret {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        self.vss_low_degree_evidence_handle
            .map(|handle| (handle, self.generation_binding_hash))
            .ok_or(CommonProofRuntimeError::WrongVerificationBinding)
    }

    fn ordered_same_secret_degree_zero_roots(
        &self,
    ) -> Result<&[[u8; Hash512::BYTE_LENGTH]], CommonProofRuntimeError> {
        if self.family != SetupKeyRelationProofFamily::SameSecret || self.source_roots.len() != 11 {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(&self.source_roots[..8])
    }

    fn require_matches_authenticated_transcript_prefix_request(
        &self,
        request: &ExactSameSecretAuthenticatedTranscriptPrefixRequest,
    ) -> Result<(), CommonProofRuntimeError> {
        self.validate()?;
        let authority_binding = request.authority_binding();
        let fiat_shamir_binding = authority_binding.fiat_shamir_binding();
        let proof_header_hash = ProofObjectHeader::from_canonical_application_statement(
            self.canonical_application_statement_bytes.to_vec(),
            &CanonicalDecodeLimits::default(),
        )
        .and_then(|header| header.proof_header_hash())
        .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?
        .into_bytes();
        if self.family != SetupKeyRelationProofFamily::SameSecret
            || self.protocol_version != fiat_shamir_binding.protocol_version()
            || self.application_slot.suite_identifier().into_bytes()
                != fiat_shamir_binding.suite_identifier()
            || self.application_slot.ceremony_context_hash().into_bytes()
                != fiat_shamir_binding.ceremony_context_hash()
            || self.application_slot.action_context_hash().into_bytes()
                != fiat_shamir_binding.action_context_hash()
            || self.participant_identity != fiat_shamir_binding.participant_identity()
            || self.roster_position() != fiat_shamir_binding.roster_position()
            || self.application_slot_hash != fiat_shamir_binding.proof_application_slot_hash()
            || self.application_statement_hash != fiat_shamir_binding.application_statement_hash()
            || proof_header_hash != fiat_shamir_binding.proof_header_hash()
            || self.relation_plan_hash != fiat_shamir_binding.relation_plan_hash()
            || self.relation_plan_variant_hash != fiat_shamir_binding.relation_plan_variant_hash()
            || self.construction_plan_identity_hash
                != fiat_shamir_binding.construction_plan_identity_hash()
            || self.source_roots.as_ref() != fiat_shamir_binding.ordered_source_roots()
            || self.generation_binding_hash != authority_binding.generation_binding_hash()
            || self.attempt_identifier != authority_binding.attempt_identifier()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(())
    }
}

fn require_generated_proof_matches_statement_source(
    source: &AuthenticatedSetupKeyRelationGenerationStatementSource,
    generated_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    source.validate()?;
    preflight_generated_common_proof_attempt_binding(
        generated_common_proof_handle,
        source.generation_binding_hash,
        source.attempt_identifier,
    )?;
    preflight_generated_common_proof_pending_statement(
        generated_common_proof_handle,
        source.family.statement_schema_identifier(),
        Some(source.roster_position()),
        None,
        &source.canonical_application_statement_bytes,
    )?;
    Ok(())
}

fn available_generation_statement_source(
    handle: u32,
    expected_family: SetupKeyRelationProofFamily,
) -> Result<AuthenticatedSetupKeyRelationGenerationStatementSource, CommonProofRuntimeError> {
    SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow()
            .available(handle, expected_family)
            .cloned()
    })
}

pub(crate) fn reserve_setup_key_relation_generation_statement_source(
    handle: u32,
    expected_family: SetupKeyRelationProofFamily,
) -> Result<AuthenticatedSetupKeyRelationGenerationStatementSource, CommonProofRuntimeError> {
    let source = available_generation_statement_source(handle, expected_family)?;
    source.validate()?;
    SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .reserve_verification(handle, expected_family)
    })
}

pub(crate) fn restore_setup_key_relation_generation_statement_source(
    handle: u32,
    expected_family: SetupKeyRelationProofFamily,
) -> Result<(), CommonProofRuntimeError> {
    SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .restore_verification(handle, expected_family)
    })
}

pub(crate) fn require_reserved_setup_key_relation_generation_statement_source(
    handle: u32,
    expected_family: SetupKeyRelationProofFamily,
    generated_common_proof_handle: u32,
) -> Result<AuthenticatedSetupKeyRelationGenerationStatementSource, CommonProofRuntimeError> {
    let source = SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY
        .with(|registry| registry.borrow().reserved(handle, expected_family).cloned())?;
    require_generated_proof_matches_statement_source(&source, generated_common_proof_handle)?;
    Ok(source)
}

pub(crate) fn consume_reserved_setup_key_relation_generation_statement_source(
    handle: u32,
    expected_family: SetupKeyRelationProofFamily,
) -> Result<(), CommonProofRuntimeError> {
    SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take_reserved(handle, expected_family)
            .map(|_| ())
    })
}

fn cancel_generated_setup_key_relation_source(
    family: SetupKeyRelationProofFamily,
    statement_source_handle: u32,
    generated_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let source = available_generation_statement_source(statement_source_handle, family)?;
    require_generated_proof_matches_statement_source(&source, generated_common_proof_handle)?;
    SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .consume_available_with(statement_source_handle, family, |source| {
                retire_generated_common_proof_capabilities(&[generated_common_proof_handle])?;
                if let Ok((evidence_handle, generation_binding_hash)) =
                    source.same_secret_low_degree_evidence_binding()
                {
                    detach_verified_vss_low_degree_evidence_from_same_secret_generation(
                        evidence_handle,
                        generation_binding_hash,
                    )?;
                }
                Ok(())
            })
    })
}

fn contribute_generated_setup_key_relation_source_to_package(
    family: SetupKeyRelationProofFamily,
    accepted_setup_package_builder_handle: u32,
    statement_source_handle: u32,
    generated_common_proof_handle: u32,
) -> Result<(), CommonProofRuntimeError> {
    let source = available_generation_statement_source(statement_source_handle, family)?;
    require_generated_proof_matches_statement_source(&source, generated_common_proof_handle)?;
    add_generated_proof_source_to_accepted_setup_package_builder(
        accepted_setup_package_builder_handle,
        generated_common_proof_handle,
        source.canonical_application_statement_bytes(),
    )
}

fn selected_setup_key_relation_proof_runtime_plan(
    family: SetupKeyRelationProofFamily,
    canonical_application_statement_bytes: &[u8],
) -> Result<SelectedSetupKeyRelationProofRuntimePlan, SetupKeyRelationRuntimeError> {
    let statement_schema_identifier = family.statement_schema_identifier();
    let relation_context = selected_relation_plan_check_context(statement_schema_identifier)
        .ok_or(SetupKeyRelationRuntimeError::Relation(
            RelationPlanError::InvalidDomain,
        ))?;
    let compiled_relation_plan = match family {
        SetupKeyRelationProofFamily::SameSecret => compile_same_secret_relation_plan(
            &selected_same_secret_relation_plan_input()?,
            &relation_context,
        )?,
        SetupKeyRelationProofFamily::PublicKeyShare => compile_public_key_share_relation_plan(
            &selected_public_key_share_relation_plan_input()?,
            &relation_context,
        )?,
    };
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        &compiled_relation_plan,
        &relation_context,
        None,
        None,
    )?;
    let limits =
        selected_proof_runtime_limits(canonical_application_statement_bytes, &relation_plan)?;
    Ok(SelectedSetupKeyRelationProofRuntimePlan {
        relation_plan,
        limits,
    })
}

fn require_selected_suite_matches_generation_source(
    selected_suite_handle: u32,
    source: &SetupGenerationKeyRelationPreparationSource,
) -> Result<(), SetupKeyRelationRuntimeError> {
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() != source.protocol_version()
            || selected_suite.suite_identifier() != source.suite_identifier()
        {
            return Err(SetupKeyRelationRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(SetupKeyRelationRuntimeError::Runtime)??;
    Ok(())
}

fn resolve_single_setup_intent_source(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
) -> Result<VerifiedBoardApplicationSource, SetupKeyRelationRuntimeError> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    let mut sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[setup_intent_object_handle],
    )
    .map_err(SetupKeyRelationRuntimeError::BoardRuntime)?;
    let source = sources.pop().ok_or(SetupKeyRelationRuntimeError::Refusal(
        RefusalReason::MissingPrerequisite,
    ))?;
    if !sources.is_empty() {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    source.setup_intent_payload()?;
    Ok(source)
}

fn require_setup_intent_matches_generation_source(
    board_source: &VerifiedBoardApplicationSource,
    source: &SetupGenerationKeyRelationPreparationSource,
) -> Result<(), SetupKeyRelationRuntimeError> {
    if board_source.object_type() != FoundationObjectType::SetupIntent
        || board_source.suite_identifier().into_bytes() != source.suite_identifier()
        || board_source.manifest_hash().into_bytes() != source.manifest_hash()
        || board_source.ceremony_context_hash().into_bytes() != source.ceremony_context_hash()
        || board_source.action_context_hash().into_bytes() != source.action_context_hash()
        || board_source.roster_hash().into_bytes() != source.roster_hash()
        || board_source.object_hash().into_bytes() != source.source_setup_intent_object_hash()
        || board_source.producer_sequence() != 0
        || board_source.producer_roster_position() != Some(source.roster_position())
        || board_source
            .producer_participant_identity()
            .map(ParticipantIdentity::into_bytes)
            != Some(source.participant_identity())
    {
        return Err(SetupKeyRelationRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    Ok(())
}

fn resolve_generation_reservation_binding(
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    source: &SetupGenerationKeyRelationPreparationSource,
) -> Result<VerifiedStateReservationRuntimeBinding, SetupKeyRelationRuntimeError> {
    if state_verifier_session_capability.len() != STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    let binding = verified_state_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
    )
    .map_err(SetupKeyRelationRuntimeError::StateRuntime)?;
    if binding.authorization_hash.into_bytes() != source.action_randomness_authorization_hash() {
        return Err(SetupKeyRelationRuntimeError::Refusal(
            RefusalReason::WrongHashOrRoot,
        ));
    }
    Ok(binding)
}

fn resolve_prepared_attempt(
    action_randomness_handle: u32,
    verified_reservation_binding: VerifiedStateReservationRuntimeBinding,
    board_source: &VerifiedBoardApplicationSource,
    source: &SetupGenerationKeyRelationPreparationSource,
    checkpoint_continuation: crate::foundation::AuthenticatedCheckpointContinuationSource,
) -> Result<PreparedActionProofAttemptSource, SetupKeyRelationRuntimeError> {
    let statement_schema_identifier = source.family().statement_schema_identifier();
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(source.suite_identifier()),
        Hash512::from_bytes(source.ceremony_context_hash()),
        Hash512::from_bytes(source.action_context_hash()),
        statement_schema_identifier,
        Some(source.roster_position()),
        None,
        None,
    )?;
    let application_statement_hash = Hash512::from_bytes(verified_application_statement_hash(
        source.protocol_version(),
        source.suite_identifier(),
        statement_schema_identifier,
        source.canonical_application_statement_bytes(),
    ));
    resolve_prepared_action_proof_attempt_source(
        action_randomness_handle,
        verified_reservation_binding,
        board_source,
        application_slot,
        application_statement_hash,
        checkpoint_continuation,
    )
    .map_err(SetupKeyRelationRuntimeError::ActionRandomnessRuntime)
}

fn prepare_common_generation(
    setup_generation_authority_handle: u32,
    preparation_source: &SetupGenerationKeyRelationPreparationSource,
    prepared_attempt: PreparedActionProofAttemptSource,
    relation_plan: CommonProofRelationPlanCapability,
    limits: CommonProofRuntimeLimits,
) -> Result<super::PreparedCommonProofGeneration, SetupKeyRelationRuntimeError> {
    let (setup_proof_context_hash, participant_identity, roster_position) =
        match preparation_source.family() {
            SetupKeyRelationProofFamily::SameSecret => {
                let statement = decode_selected_same_secret_statement(
                    preparation_source.canonical_application_statement_bytes(),
                    super::SelectedApplicationStatementContext::new(
                        preparation_source.protocol_version(),
                        preparation_source.suite_identifier(),
                        None,
                        None,
                    ),
                )
                .map_err(|_| SetupKeyRelationRuntimeError::Refusal(RefusalReason::WrongContext))?;
                (
                    statement.setup_proof_context_hash(),
                    statement.participant_identity(),
                    statement.roster_position(),
                )
            }
            SetupKeyRelationProofFamily::PublicKeyShare => {
                let statement = decode_selected_public_key_share_statement(
                    preparation_source.canonical_application_statement_bytes(),
                    super::SelectedApplicationStatementContext::new(
                        preparation_source.protocol_version(),
                        preparation_source.suite_identifier(),
                        None,
                        None,
                    ),
                )
                .map_err(|_| SetupKeyRelationRuntimeError::Refusal(RefusalReason::WrongContext))?;
                (
                    statement.setup_proof_context_hash(),
                    statement.participant_identity(),
                    statement.roster_position(),
                )
            }
        };
    let application = SetupGenerationKeyRelationApplication::from_runtime_binding(
        preparation_source.family(),
        prepared_attempt,
        preparation_source.canonical_application_statement_bytes(),
        setup_proof_context_hash,
        preparation_source.roster_hash(),
        participant_identity,
        roster_position,
    );
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    with_setup_generation_key_relation(&authority_handle, &application, |source| {
        source.prepare_common_generation(relation_plan, limits)
    })
    .map_err(SetupKeyRelationRuntimeError::GenerationPreparation)
}

fn resumed_generation_preparation_error(
    error: SetupKeyRelationRuntimeError,
) -> CommonProofGenerationPreparationError {
    match error {
        SetupKeyRelationRuntimeError::Runtime(error) => {
            CommonProofGenerationPreparationError::Runtime(error)
        }
        SetupKeyRelationRuntimeError::GenerationPreparation(
            SetupKeyRelationGenerationPreparationError::Runtime(error),
        ) => CommonProofGenerationPreparationError::Runtime(error),
        SetupKeyRelationRuntimeError::GenerationPreparation(
            SetupKeyRelationGenerationPreparationError::Preparation(error),
        ) => error,
        SetupKeyRelationRuntimeError::GenerationPreparation(
            SetupKeyRelationGenerationPreparationError::Refusal(RefusalReason::ConsumedState),
        ) => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::UnknownOrStaleHandle,
        ),
        _ => CommonProofGenerationPreparationError::Runtime(
            CommonProofRuntimeError::WrongVerificationBinding,
        ),
    }
}

#[derive(Clone, Copy)]
enum GenerationMode {
    Fresh,
    Resume,
}

#[allow(clippy::too_many_arguments)]
fn prepare_generation(
    family: SetupKeyRelationProofFamily,
    vss_low_degree_evidence_handle: Option<u32>,
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability: &[u8],
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: GenerationMode,
) -> Result<(u32, u32), SetupKeyRelationRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    let authority_handle =
        SetupGenerationAuthorityHandle::from_identifier(setup_generation_authority_handle);
    let preparation_source =
        resolve_setup_generation_key_relation_preparation_source(&authority_handle, family)?;
    if preparation_source.family() != family {
        return Err(SetupKeyRelationRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ));
    }
    require_selected_suite_matches_generation_source(selected_suite_handle, &preparation_source)?;
    let board_source = resolve_single_setup_intent_source(
        board_verifier_session_handle,
        board_verifier_session_capability,
        setup_intent_object_handle,
    )?;
    require_setup_intent_matches_generation_source(&board_source, &preparation_source)?;
    let verified_reservation_binding = resolve_generation_reservation_binding(
        state_verifier_session_handle,
        state_verifier_session_capability,
        verified_reservation_handle,
        &preparation_source,
    )?;
    let runtime_plan = selected_setup_key_relation_proof_runtime_plan(
        family,
        preparation_source.canonical_application_statement_bytes(),
    )?;
    let construction_binding =
        SetupKeyRelationConstructionBinding::from_relation_plan(&runtime_plan.relation_plan);
    let checkpoint_schedule_digest = runtime_plan.relation_plan.checkpoint_schedule_digest()?;
    let fresh_continuation =
        crate::foundation::AuthenticatedCheckpointContinuationSource::for_fresh_common_proof_attempt(
            checkpoint_lineage_identifier,
            checkpoint_schedule_digest,
        );
    let fresh_prepared_attempt = resolve_prepared_attempt(
        action_randomness_handle,
        verified_reservation_binding,
        &board_source,
        &preparation_source,
        fresh_continuation,
    )?;
    let generation_family_adapter = match generation_mode {
        GenerationMode::Fresh => {
            CommonProofGenerationFamilyAdapter::fresh(prepare_common_generation(
                setup_generation_authority_handle,
                &preparation_source,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?)
        }
        GenerationMode::Resume => {
            let fresh_preparation = prepare_common_generation(
                setup_generation_authority_handle,
                &preparation_source,
                fresh_prepared_attempt,
                runtime_plan.relation_plan,
                runtime_plan.limits,
            )?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
                fresh_preparation.application_statement_schema_identifier(),
                fresh_preparation.runtime_binding_hash(),
                fresh_preparation.generation_authorization_hash(),
                fresh_preparation.proof_attempt_lineage_identifier(),
            );
            drop(fresh_preparation);
            let resumed_preparation_source = preparation_source.clone();
            CommonProofGenerationFamilyAdapter::resume(
                description,
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
                Box::new(move |authenticated_continuation| {
                    let resumed_runtime_plan = selected_setup_key_relation_proof_runtime_plan(
                        family,
                        resumed_preparation_source.canonical_application_statement_bytes(),
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    let prepared_attempt = resolve_prepared_attempt(
                        action_randomness_handle,
                        verified_reservation_binding,
                        &board_source,
                        &resumed_preparation_source,
                        authenticated_continuation,
                    )
                    .map_err(resumed_generation_preparation_error)?;
                    prepare_common_generation(
                        setup_generation_authority_handle,
                        &resumed_preparation_source,
                        prepared_attempt,
                        resumed_runtime_plan.relation_plan,
                        resumed_runtime_plan.limits,
                    )
                    .map_err(resumed_generation_preparation_error)
                }),
            )
        }
    };
    let statement_source =
        AuthenticatedSetupKeyRelationGenerationStatementSource::from_production_authority(
            &preparation_source,
            construction_binding,
            generation_family_adapter.description(),
            vss_low_degree_evidence_handle,
        )?;
    if let Some(evidence_handle) = vss_low_degree_evidence_handle {
        attach_verified_vss_low_degree_evidence_to_same_secret_generation(
            evidence_handle,
            statement_source.generation_binding_hash,
            &preparation_source,
            statement_source.ordered_same_secret_degree_zero_roots()?,
        )?;
    }
    let statement_source_handle = SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY
        .with(|registry| registry.borrow_mut().retain(statement_source));
    let statement_source_handle = match statement_source_handle {
        Ok(handle) => handle,
        Err(error) => {
            if let Some(evidence_handle) = vss_low_degree_evidence_handle {
                detach_verified_vss_low_degree_evidence_from_same_secret_generation(
                    evidence_handle,
                    generation_family_adapter
                        .description()
                        .common_proof_generation_authorization_hash(),
                )?;
            }
            return Err(SetupKeyRelationRuntimeError::Runtime(error));
        }
    };
    match retain_common_proof_generation_family_adapter(generation_family_adapter) {
        Ok(adapter_handle) => Ok((adapter_handle, statement_source_handle)),
        Err(error) => {
            let source =
                SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY.with(|registry| {
                    registry
                        .borrow_mut()
                        .take_available(statement_source_handle, family)
                })?;
            if let Ok((evidence_handle, generation_binding_hash)) =
                source.same_secret_low_degree_evidence_binding()
            {
                detach_verified_vss_low_degree_evidence_from_same_secret_generation(
                    evidence_handle,
                    generation_binding_hash,
                )?;
            }
            Err(SetupKeyRelationRuntimeError::Runtime(error))
        }
    }
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn runtime_error_status(error: SetupKeyRelationRuntimeError) -> u32 {
    match error {
        SetupKeyRelationRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        SetupKeyRelationRuntimeError::GenerationPreparation(error) => match error {
            SetupKeyRelationGenerationPreparationError::Refusal(refusal_reason) => {
                refusal_status(refusal_reason)
            }
            SetupKeyRelationGenerationPreparationError::Runtime(error) => {
                super::runtime_ffi::runtime_error_status(error)
            }
            SetupKeyRelationGenerationPreparationError::Preparation(error) => match error {
                CommonProofGenerationPreparationError::Runtime(error) => {
                    super::runtime_ffi::runtime_error_status(error)
                }
                CommonProofGenerationPreparationError::Generation(error) => {
                    let _ = error;
                    refusal_status(RefusalReason::OutsideSupportedProfile)
                }
            },
            SetupKeyRelationGenerationPreparationError::Prover(error) => {
                let _ = error;
                refusal_status(RefusalReason::InvalidArithmeticRelation)
            }
        },
        SetupKeyRelationRuntimeError::Foundation(error) => refusal_status(error.refusal_reason),
        SetupKeyRelationRuntimeError::ActionRandomnessRuntime(status)
        | SetupKeyRelationRuntimeError::BoardRuntime(status)
        | SetupKeyRelationRuntimeError::StateRuntime(status) => status,
        SetupKeyRelationRuntimeError::Refusal(refusal_reason) => refusal_status(refusal_reason),
        SetupKeyRelationRuntimeError::InvalidInput => {
            refusal_status(RefusalReason::WrongTypeOrLength)
        }
        SetupKeyRelationRuntimeError::Accounting(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        SetupKeyRelationRuntimeError::Profile(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        SetupKeyRelationRuntimeError::Relation(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        SetupKeyRelationRuntimeError::RelationCapability(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
    declared_byte_length: usize,
) -> Result<[u8; BYTE_LENGTH], SetupKeyRelationRuntimeError> {
    if pointer.is_null() || declared_byte_length != BYTE_LENGTH {
        return Err(SetupKeyRelationRuntimeError::InvalidInput);
    }
    let bytes = unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) };
    bytes
        .try_into()
        .map_err(|_| SetupKeyRelationRuntimeError::InvalidInput)
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_from_ffi_inputs(
    family: SetupKeyRelationProofFamily,
    vss_low_degree_evidence_handle: Option<u32>,
    selected_suite_handle: u32,
    setup_generation_authority_handle: u32,
    action_randomness_handle: u32,
    state_verifier_session_handle: u32,
    state_verifier_session_capability_pointer: *const u8,
    state_verifier_session_capability_byte_length: usize,
    verified_reservation_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    setup_intent_object_handle: u32,
    checkpoint_lineage_identifier_pointer: *const u8,
    checkpoint_lineage_identifier_byte_length: usize,
    statement_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: GenerationMode,
) -> u32 {
    let result = (|| {
        if statement_source_handle_output_pointer.is_null() {
            return Err(SetupKeyRelationRuntimeError::InvalidInput);
        }
        let state_verifier_session_capability = unsafe {
            fixed_input::<STATE_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                state_verifier_session_capability_pointer,
                state_verifier_session_capability_byte_length,
            )
        }?;
        let board_verifier_session_capability = unsafe {
            fixed_input::<BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH>(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        }?;
        let checkpoint_lineage_identifier = unsafe {
            fixed_input::<ATTEMPT_IDENTIFIER_BYTE_LENGTH>(
                checkpoint_lineage_identifier_pointer,
                checkpoint_lineage_identifier_byte_length,
            )
        }?;
        prepare_generation(
            family,
            vss_low_degree_evidence_handle,
            selected_suite_handle,
            setup_generation_authority_handle,
            action_randomness_handle,
            state_verifier_session_handle,
            &state_verifier_session_capability,
            verified_reservation_handle,
            board_verifier_session_handle,
            &board_verifier_session_capability,
            setup_intent_object_handle,
            checkpoint_lineage_identifier,
            generation_mode,
        )
    })();
    match result {
        Ok((adapter_handle, statement_source_handle)) => {
            unsafe {
                statement_source_handle_output_pointer.write(statement_source_handle);
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

macro_rules! same_secret_generation_entry_point {
    ($name:ident, $mode:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            selected_suite_handle: u32,
            setup_generation_authority_handle: u32,
            vss_low_degree_evidence_handle: u32,
            action_randomness_handle: u32,
            state_verifier_session_handle: u32,
            state_verifier_session_capability_pointer: *const u8,
            state_verifier_session_capability_byte_length: usize,
            verified_reservation_handle: u32,
            board_verifier_session_handle: u32,
            board_verifier_session_capability_pointer: *const u8,
            board_verifier_session_capability_byte_length: usize,
            setup_intent_object_handle: u32,
            checkpoint_lineage_identifier_pointer: *const u8,
            checkpoint_lineage_identifier_byte_length: usize,
            statement_source_handle_output_pointer: *mut u32,
            status_pointer: *mut u32,
        ) -> u32 {
            unsafe {
                prepare_generation_from_ffi_inputs(
                    SetupKeyRelationProofFamily::SameSecret,
                    Some(vss_low_degree_evidence_handle),
                    selected_suite_handle,
                    setup_generation_authority_handle,
                    action_randomness_handle,
                    state_verifier_session_handle,
                    state_verifier_session_capability_pointer,
                    state_verifier_session_capability_byte_length,
                    verified_reservation_handle,
                    board_verifier_session_handle,
                    board_verifier_session_capability_pointer,
                    board_verifier_session_capability_byte_length,
                    setup_intent_object_handle,
                    checkpoint_lineage_identifier_pointer,
                    checkpoint_lineage_identifier_byte_length,
                    statement_source_handle_output_pointer,
                    status_pointer,
                    $mode,
                )
            }
        }
    };
}

same_secret_generation_entry_point!(
    sealed_lattice_same_secret_prepare_generation,
    GenerationMode::Fresh
);
same_secret_generation_entry_point!(
    sealed_lattice_same_secret_prepare_resumed_generation,
    GenerationMode::Resume
);

macro_rules! public_key_share_generation_entry_point {
    ($name:ident, $mode:expr) => {
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name(
            selected_suite_handle: u32,
            setup_generation_authority_handle: u32,
            action_randomness_handle: u32,
            state_verifier_session_handle: u32,
            state_verifier_session_capability_pointer: *const u8,
            state_verifier_session_capability_byte_length: usize,
            verified_reservation_handle: u32,
            board_verifier_session_handle: u32,
            board_verifier_session_capability_pointer: *const u8,
            board_verifier_session_capability_byte_length: usize,
            setup_intent_object_handle: u32,
            checkpoint_lineage_identifier_pointer: *const u8,
            checkpoint_lineage_identifier_byte_length: usize,
            statement_source_handle_output_pointer: *mut u32,
            status_pointer: *mut u32,
        ) -> u32 {
            unsafe {
                prepare_generation_from_ffi_inputs(
                    SetupKeyRelationProofFamily::PublicKeyShare,
                    None,
                    selected_suite_handle,
                    setup_generation_authority_handle,
                    action_randomness_handle,
                    state_verifier_session_handle,
                    state_verifier_session_capability_pointer,
                    state_verifier_session_capability_byte_length,
                    verified_reservation_handle,
                    board_verifier_session_handle,
                    board_verifier_session_capability_pointer,
                    board_verifier_session_capability_byte_length,
                    setup_intent_object_handle,
                    checkpoint_lineage_identifier_pointer,
                    checkpoint_lineage_identifier_byte_length,
                    statement_source_handle_output_pointer,
                    status_pointer,
                    $mode,
                )
            }
        }
    };
}

public_key_share_generation_entry_point!(
    sealed_lattice_public_key_share_prepare_generation,
    GenerationMode::Fresh
);
public_key_share_generation_entry_point!(
    sealed_lattice_public_key_share_prepare_resumed_generation,
    GenerationMode::Resume
);

fn supply_same_secret_authenticated_transcript_prefix(
    statement_source_handle: u32,
    operation_handle: u32,
) -> Result<(), SetupKeyRelationRuntimeError> {
    let source = available_generation_statement_source(
        statement_source_handle,
        SetupKeyRelationProofFamily::SameSecret,
    )?;
    let request =
        common_proof_generation_authenticated_transcript_prefix_request(operation_handle)?;
    source.require_matches_authenticated_transcript_prefix_request(&request)?;
    let runtime_plan = selected_setup_key_relation_proof_runtime_plan(
        SetupKeyRelationProofFamily::SameSecret,
        source.canonical_application_statement_bytes(),
    )?;
    let (evidence_handle, generation_binding_hash) =
        source.same_secret_low_degree_evidence_binding()?;
    let prepared = with_attached_verified_vss_low_degree_evidence(
        evidence_handle,
        generation_binding_hash,
        |evidence| {
            PreparedExactSameSecretTranscriptPrefix::prepare(
                request,
                evidence,
                &runtime_plan.relation_plan,
            )
            .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)
        },
    )?;
    supply_common_proof_generation_authenticated_transcript_prefix(operation_handle, prepared)?;
    Ok(())
}

/// Installs the exact authenticated Fiat-Shamir prefix without accepting any
/// caller-supplied transcript bytes, roots, points, counts, or layout values.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_same_secret_generation_supply_authenticated_transcript_prefix(
    statement_source_handle: u32,
    operation_handle: u32,
) -> u32 {
    supply_same_secret_authenticated_transcript_prefix(statement_source_handle, operation_handle)
        .map_or_else(runtime_error_status, |()| 0)
}

macro_rules! generated_source_entry_points {
    ($cancel_name:ident, $contribute_name:ident, $family:expr) => {
        #[unsafe(no_mangle)]
        pub extern "C" fn $cancel_name(
            statement_source_handle: u32,
            generated_common_proof_handle: u32,
        ) -> u32 {
            cancel_generated_setup_key_relation_source(
                $family,
                statement_source_handle,
                generated_common_proof_handle,
            )
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
        }

        #[unsafe(no_mangle)]
        pub extern "C" fn $contribute_name(
            accepted_setup_package_builder_handle: u32,
            statement_source_handle: u32,
            generated_common_proof_handle: u32,
        ) -> u32 {
            contribute_generated_setup_key_relation_source_to_package(
                $family,
                accepted_setup_package_builder_handle,
                statement_source_handle,
                generated_common_proof_handle,
            )
            .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
        }
    };
}

generated_source_entry_points!(
    sealed_lattice_same_secret_generation_cancel,
    sealed_lattice_same_secret_generation_contribute_package,
    SetupKeyRelationProofFamily::SameSecret
);
generated_source_entry_points!(
    sealed_lattice_public_key_share_generation_cancel,
    sealed_lattice_public_key_share_generation_contribute_package,
    SetupKeyRelationProofFamily::PublicKeyShare
);

#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_setup_key_relation_generation_statement_discard(
    statement_source_handle: u32,
) -> u32 {
    SETUP_KEY_RELATION_GENERATION_STATEMENT_SOURCE_REGISTRY
        .with(|registry| {
            let mut registry = registry.borrow_mut();
            let source = match registry.sources.get(&statement_source_handle) {
                Some(SetupKeyRelationGenerationStatementSourceState::Available(source)) => source,
                Some(SetupKeyRelationGenerationStatementSourceState::VerificationReserved(_)) => {
                    return Err(CommonProofRuntimeError::WrongOperationPhase);
                }
                None => return Err(CommonProofRuntimeError::UnknownOrStaleHandle),
            };
            if let Ok((evidence_handle, generation_binding_hash)) =
                source.same_secret_low_degree_evidence_binding()
            {
                detach_verified_vss_low_degree_evidence_from_same_secret_generation(
                    evidence_handle,
                    generation_binding_hash,
                )?;
            }
            registry.sources.remove(&statement_source_handle);
            Ok(())
        })
        .map_or_else(super::runtime_ffi::runtime_error_status, |()| 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bgv::proof_suite::{
            canonical_selected_public_key_share_statement, canonical_selected_same_secret_statement,
        },
        foundation::FOUNDATION_PROFILE,
    };

    fn valid_test_statement_source(
        family: SetupKeyRelationProofFamily,
    ) -> AuthenticatedSetupKeyRelationGenerationStatementSource {
        let participant_identity = [0x55; Hash512::BYTE_LENGTH];
        let anchor_roots = [
            [0x81; Hash512::BYTE_LENGTH],
            [0x82; Hash512::BYTE_LENGTH],
            [0x83; Hash512::BYTE_LENGTH],
        ];
        let (canonical_application_statement_bytes, source_roots) = match family {
            SetupKeyRelationProofFamily::SameSecret => {
                let degree_zero_roots = (0..8)
                    .map(|ordinal| [0x70 + ordinal; Hash512::BYTE_LENGTH])
                    .collect::<Vec<_>>();
                let canonical_application_statement_bytes =
                    canonical_selected_same_secret_statement(
                        [0x41; Hash512::BYTE_LENGTH],
                        participant_identity,
                        3,
                        &degree_zero_roots,
                        &anchor_roots,
                    )
                    .expect("test same-secret statement is canonical");
                let mut source_roots = degree_zero_roots;
                source_roots.extend_from_slice(&anchor_roots);
                (canonical_application_statement_bytes, source_roots)
            }
            SetupKeyRelationProofFamily::PublicKeyShare => {
                let public_key_share_root = [0x91; Hash512::BYTE_LENGTH];
                let canonical_application_statement_bytes =
                    canonical_selected_public_key_share_statement(
                        [0x42; Hash512::BYTE_LENGTH],
                        participant_identity,
                        3,
                        &anchor_roots,
                        public_key_share_root,
                    )
                    .expect("test public-key-share statement is canonical");
                let mut source_roots = anchor_roots.to_vec();
                source_roots.push(public_key_share_root);
                (canonical_application_statement_bytes, source_roots)
            }
        };
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            family.statement_schema_identifier(),
            Some(3),
            None,
            None,
        )
        .expect("test application slot is canonical");
        let runtime_plan = selected_setup_key_relation_proof_runtime_plan(
            family,
            &canonical_application_statement_bytes,
        )
        .expect("test statement has the selected relation plan");
        AuthenticatedSetupKeyRelationGenerationStatementSource {
            family,
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            application_slot_hash: application_slot
                .hash()
                .expect("test application slot hashes")
                .into_bytes(),
            application_slot,
            application_statement_hash: verified_application_statement_hash(
                FOUNDATION_PROFILE.protocol_version,
                [0x11; Hash512::BYTE_LENGTH],
                family.statement_schema_identifier(),
                &canonical_application_statement_bytes,
            ),
            participant_identity,
            source_roots: source_roots.into_boxed_slice(),
            relation_plan_hash: runtime_plan.relation_plan.relation_plan_hash(),
            relation_plan_variant_hash: runtime_plan.relation_plan.relation_plan_variant_hash(),
            construction_plan_identity_hash: runtime_plan
                .relation_plan
                .row_code_whir_construction_plan_identity_hash(),
            generation_binding_hash: [0xaa; Hash512::BYTE_LENGTH],
            attempt_identifier: [0xbb; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
            vss_low_degree_evidence_handle: (family == SetupKeyRelationProofFamily::SameSecret)
                .then_some(7),
            canonical_application_statement_bytes: canonical_application_statement_bytes
                .into_boxed_slice(),
        }
    }

    fn registry_test_statement_source(
        family: SetupKeyRelationProofFamily,
    ) -> AuthenticatedSetupKeyRelationGenerationStatementSource {
        let application_slot = ProofApplicationSlot::new(
            Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            family.statement_schema_identifier(),
            Some(3),
            None,
            None,
        )
        .expect("registry test application slot is canonical");
        AuthenticatedSetupKeyRelationGenerationStatementSource {
            family,
            protocol_version: FOUNDATION_PROFILE.protocol_version,
            application_slot_hash: application_slot
                .hash()
                .expect("registry test application slot hashes")
                .into_bytes(),
            application_slot,
            application_statement_hash: [0x44; Hash512::BYTE_LENGTH],
            participant_identity: [0x55; Hash512::BYTE_LENGTH],
            source_roots: vec![[0x66; Hash512::BYTE_LENGTH]].into_boxed_slice(),
            relation_plan_hash: [0x77; Hash512::BYTE_LENGTH],
            relation_plan_variant_hash: [0x88; Hash512::BYTE_LENGTH],
            construction_plan_identity_hash: [0x99; Hash512::BYTE_LENGTH],
            generation_binding_hash: [0xaa; Hash512::BYTE_LENGTH],
            attempt_identifier: [0xbb; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
            vss_low_degree_evidence_handle: (family == SetupKeyRelationProofFamily::SameSecret)
                .then_some(7),
            canonical_application_statement_bytes: vec![0xcc].into_boxed_slice(),
        }
    }

    #[test]
    fn authenticated_statement_source_refuses_statement_and_source_root_substitution() {
        let source = valid_test_statement_source(SetupKeyRelationProofFamily::SameSecret);
        source
            .validate()
            .expect("authority-derived source validates");

        let mut changed_statement = source.clone();
        let final_byte_index = changed_statement
            .canonical_application_statement_bytes
            .len()
            .checked_sub(1)
            .expect("canonical statement is nonempty");
        changed_statement.canonical_application_statement_bytes[final_byte_index] ^= 1;
        assert!(matches!(
            changed_statement.validate(),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));

        let mut changed_source_roots = source;
        changed_source_roots.source_roots[0][0] ^= 1;
        assert!(matches!(
            changed_source_roots.validate(),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
    }

    #[test]
    fn statement_source_handle_registry_never_reuses_released_handles() {
        let mut registry = SetupKeyRelationGenerationStatementSourceRegistry::default();
        let first_handle = registry
            .retain(registry_test_statement_source(
                SetupKeyRelationProofFamily::SameSecret,
            ))
            .expect("first source handle retains");
        registry
            .take_available(first_handle, SetupKeyRelationProofFamily::SameSecret)
            .expect("first source handle consumes its one-shot source");
        assert!(matches!(
            registry.take_available(first_handle, SetupKeyRelationProofFamily::SameSecret),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
        let second_handle = registry
            .retain(registry_test_statement_source(
                SetupKeyRelationProofFamily::PublicKeyShare,
            ))
            .expect("second source handle retains");
        assert_ne!(second_handle, first_handle);
    }

    #[test]
    fn statement_source_handle_registry_rejects_stale_and_out_of_capacity_access() {
        let mut registry = SetupKeyRelationGenerationStatementSourceRegistry::default();
        assert!(matches!(
            registry.take_available(91, SetupKeyRelationProofFamily::SameSecret),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
        for _ in 0..MAXIMUM_RETAINED_GENERATION_STATEMENT_SOURCE_COUNT {
            registry
                .retain(registry_test_statement_source(
                    SetupKeyRelationProofFamily::SameSecret,
                ))
                .expect("source handle within the exact bound retains");
        }
        assert!(matches!(
            registry.retain(registry_test_statement_source(
                SetupKeyRelationProofFamily::PublicKeyShare,
            )),
            Err(CommonProofRuntimeError::AllocationLimitExceeded)
        ));
    }

    #[test]
    fn statement_source_reservation_is_exclusive_and_restorable() {
        let mut registry = SetupKeyRelationGenerationStatementSourceRegistry::default();
        let handle = registry
            .retain(registry_test_statement_source(
                SetupKeyRelationProofFamily::SameSecret,
            ))
            .expect("same-secret source retains");
        let reserved = registry
            .reserve_verification(handle, SetupKeyRelationProofFamily::SameSecret)
            .expect("same-secret source reserves for verification");
        assert_eq!(
            reserved.attempt_identifier,
            [0xbb; ATTEMPT_IDENTIFIER_BYTE_LENGTH]
        );
        assert!(matches!(
            registry.reserve_verification(handle, SetupKeyRelationProofFamily::SameSecret),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));
        assert!(matches!(
            registry.take_available(handle, SetupKeyRelationProofFamily::SameSecret),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));
        registry
            .restore_verification(handle, SetupKeyRelationProofFamily::SameSecret)
            .expect("failed verification restores the source");
        assert_eq!(
            registry
                .take_available(handle, SetupKeyRelationProofFamily::SameSecret)
                .expect("restored source remains cancellable")
                .generation_binding_hash,
            [0xaa; Hash512::BYTE_LENGTH]
        );
    }

    #[test]
    fn statement_source_reservation_refuses_family_substitution_and_is_one_shot() {
        let mut registry = SetupKeyRelationGenerationStatementSourceRegistry::default();
        let handle = registry
            .retain(registry_test_statement_source(
                SetupKeyRelationProofFamily::PublicKeyShare,
            ))
            .expect("public-key-share source retains");
        assert!(matches!(
            registry.reserve_verification(handle, SetupKeyRelationProofFamily::SameSecret),
            Err(CommonProofRuntimeError::WrongOperationPhase)
        ));
        registry
            .reserve_verification(handle, SetupKeyRelationProofFamily::PublicKeyShare)
            .expect("the exact family reserves");
        registry
            .take_reserved(handle, SetupKeyRelationProofFamily::PublicKeyShare)
            .expect("positive verification consumes the reserved source");
        assert!(matches!(
            registry.restore_verification(handle, SetupKeyRelationProofFamily::PublicKeyShare),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }

    #[test]
    fn cancellation_restores_the_source_after_retirement_failure_then_consumes_it_once() {
        let mut registry = SetupKeyRelationGenerationStatementSourceRegistry::default();
        let handle = registry
            .retain(registry_test_statement_source(
                SetupKeyRelationProofFamily::SameSecret,
            ))
            .expect("same-secret source retains");
        assert!(matches!(
            registry.consume_available_with(
                handle,
                SetupKeyRelationProofFamily::SameSecret,
                |_| Err(CommonProofRuntimeError::WrongVerificationBinding),
            ),
            Err(CommonProofRuntimeError::WrongVerificationBinding)
        ));
        assert_eq!(
            registry
                .available(handle, SetupKeyRelationProofFamily::SameSecret)
                .expect("failed proof retirement restores the exact source")
                .attempt_identifier,
            [0xbb; ATTEMPT_IDENTIFIER_BYTE_LENGTH]
        );
        registry
            .consume_available_with(handle, SetupKeyRelationProofFamily::SameSecret, |_| Ok(()))
            .expect("successful proof retirement consumes the source");
        assert!(matches!(
            registry.available(handle, SetupKeyRelationProofFamily::SameSecret),
            Err(CommonProofRuntimeError::UnknownOrStaleHandle)
        ));
    }
}
