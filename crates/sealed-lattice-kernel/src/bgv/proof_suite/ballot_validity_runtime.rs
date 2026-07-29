//! Browser/WASM runtime adapter for the selected ballot-validity family.
//!
//! The factory derives every proof binding from live selected-suite,
//! action-randomness, and accepted-setup capabilities. Its only transported
//! inputs are the ballot scores, producer sequence, and fresh local attempt
//! identifiers. The generated ciphertext remains joined to the common-proof
//! attempt through shared immutable residue buffers and is exposed only as an
//! authenticated canonical stream.

use core::{mem::size_of, slice};
use std::{cell::RefCell, collections::BTreeMap, sync::Arc};

use zeroize::{Zeroize, Zeroizing};

#[cfg(test)]
use crate::bgv::{
    coefficient_codec::canonical_modulus_byte_length,
    direct_ballots::PAIR_CHARACTER_CIPHERTEXT_COUNT,
    parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
};
#[cfg(test)]
use crate::foundation::{CanonicalStreamWriter, selected_suite_capability_for_tests};

use crate::{
    bgv::setup::{VerifiedAcceptedSetupAuthorityHandle, with_verified_accepted_setup_authority},
    encoding::{CanonicalError, CanonicalErrorCode},
    foundation::{
        ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT, ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE,
        BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH, BallotPackagePayload, CanonicalDecodeLimits,
        CanonicalStreamDomain, FOUNDATION_PROFILE, FoundationObjectType, FoundationSchemaError,
        Hash512, ML_DSA_65_SIGNATURE_BYTE_LENGTH, ObjectEnvelope, ParticipantIdentity,
        PreparedSignedCarrierDescription, ProofApplicationBinding, ProofApplicationSlot,
        ProofApplicationSlotCeilings, ProofObjectHeader, RefusalReason, Roster, StreamDescriptor,
        VerifiedBallotPackageApplicationPayload, VerifiedBoardApplicationSource,
        cancel_prepared_signed_carrier, finish_prepared_signed_carrier,
        prepared_signed_carrier_byte_length, resolve_verified_board_application_sources,
        retain_action_private_randomness_for_exact_family, retain_prepared_signed_carrier,
    },
    hashing::hash_framed_parts_512,
};

use super::application_statement::SelectedBallotValidityStatement;
use super::runtime::CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN;
use super::runtime_ffi::{
    CommonProofGenerationFamilyAdapter, CommonProofGenerationFamilyAdapterDescription,
    bind_generated_common_proof_to_verified_board_source,
    retain_common_proof_generation_family_adapter,
    retain_common_proof_verification_family_adapter_from_upstream,
    with_common_proof_selected_suite,
};
use super::{
    BallotValidityAcceptedSetupBinding, BallotValidityAdapterError,
    BallotValidityBoundPublicMaterial, BallotValidityCiphertextReadback,
    BallotValidityCiphertextStreamDecoder, BallotValidityGenerationPreparationError,
    BallotValidityPreparedProofAttempt, BallotValidityVerifiedColumnEvaluator,
    BorrowedVerifiedCommonProofCapability, CommonProofGenerationPreparationError,
    CommonProofRelationPlanCapability, CommonProofRelationPlanCapabilityError,
    CommonProofRuntimeError, CommonProofSelectedSuiteCapabilityHandle,
    ConsumedVerifiedCommonProofCapability, MAXIMUM_COMMON_PROOF_BYTE_LENGTH, RelationPlanError,
    SelectedApplicationStatementContext, SelectedProofAccountingError,
    VerifiedCommonProofStatementSource, canonical_selected_ballot_validity_statement,
    decode_selected_ballot_validity_statement, selected_ballot_validity_relation_compilation,
    selected_proof_runtime_limits, selected_relation_plan_check_context,
    verified_application_statement_hash,
};

const BALLOT_SCORE_COUNT: usize = 20;
const BALLOT_SCORE_INPUT_BYTE_LENGTH: usize = BALLOT_SCORE_COUNT * size_of::<u64>();
const ATTEMPT_IDENTIFIER_BYTE_LENGTH: usize = 32;
const MAXIMUM_VERIFIED_BALLOT_OUTPUT_COUNT: usize = 1;

#[derive(Debug)]
enum BallotValidityRuntimeError {
    Adapter(BallotValidityAdapterError),
    Accounting(SelectedProofAccountingError),
    Relation(RelationPlanError),
    RelationCapability(CommonProofRelationPlanCapabilityError),
    GenerationPreparation(BallotValidityGenerationPreparationError),
    Runtime(CommonProofRuntimeError),
    ActionRandomness(u32),
    BoardRuntime(u32),
    Refusal(RefusalReason),
    Schema(FoundationSchemaError),
    Canonical(CanonicalError),
    InvalidInput,
    WrongReadbackPhase,
}

impl From<BallotValidityAdapterError> for BallotValidityRuntimeError {
    fn from(error: BallotValidityAdapterError) -> Self {
        Self::Adapter(error)
    }
}

impl From<SelectedProofAccountingError> for BallotValidityRuntimeError {
    fn from(error: SelectedProofAccountingError) -> Self {
        Self::Accounting(error)
    }
}

impl From<RelationPlanError> for BallotValidityRuntimeError {
    fn from(error: RelationPlanError) -> Self {
        Self::Relation(error)
    }
}

impl From<CommonProofRelationPlanCapabilityError> for BallotValidityRuntimeError {
    fn from(error: CommonProofRelationPlanCapabilityError) -> Self {
        Self::RelationCapability(error)
    }
}

impl From<BallotValidityGenerationPreparationError> for BallotValidityRuntimeError {
    fn from(error: BallotValidityGenerationPreparationError) -> Self {
        Self::GenerationPreparation(error)
    }
}

impl From<CommonProofRuntimeError> for BallotValidityRuntimeError {
    fn from(error: CommonProofRuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<FoundationSchemaError> for BallotValidityRuntimeError {
    fn from(error: FoundationSchemaError) -> Self {
        Self::Schema(error)
    }
}

impl From<CanonicalError> for BallotValidityRuntimeError {
    fn from(error: CanonicalError) -> Self {
        Self::Canonical(error)
    }
}

struct BallotCiphertextReadbackEntry {
    descriptor: StreamDescriptor,
    descriptor_bytes: Box<[u8]>,
    descriptor_total_byte_length: u64,
    descriptor_chunk_count: usize,
    next_chunk_index: usize,
    readback_complete: bool,
    canonical_application_statement_bytes: Box<[u8]>,
    ballot_package_statement: SelectedBallotValidityStatement,
    readback: BallotValidityCiphertextReadback,
}

#[derive(Default)]
struct BallotCiphertextReadbackRegistry {
    active: Option<(u32, BallotCiphertextReadbackEntry)>,
    next_handle: u32,
}

impl BallotCiphertextReadbackRegistry {
    fn retain(
        &mut self,
        entry: BallotCiphertextReadbackEntry,
    ) -> Result<u32, BallotValidityRuntimeError> {
        if self.active.is_some() {
            return Err(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ));
        }
        let handle = if self.next_handle == 0 {
            1
        } else {
            self.next_handle
        };
        self.next_handle = handle.checked_add(1).filter(|next| *next != 0).ok_or(
            BallotValidityRuntimeError::Runtime(CommonProofRuntimeError::AllocationLimitExceeded),
        )?;
        self.active = Some((handle, entry));
        Ok(handle)
    }

    fn entry(
        &self,
        handle: u32,
    ) -> Result<&BallotCiphertextReadbackEntry, BallotValidityRuntimeError> {
        self.active
            .as_ref()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, entry)| entry)
            .ok_or(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }

    fn entry_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut BallotCiphertextReadbackEntry, BallotValidityRuntimeError> {
        self.active
            .as_mut()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, entry)| entry)
            .ok_or(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }

    fn finish_readback(&mut self, handle: u32) -> Result<(), BallotValidityRuntimeError> {
        let entry = self.entry_mut(handle)?;
        if entry.readback_complete || entry.next_chunk_index != entry.descriptor_chunk_count {
            return Err(BallotValidityRuntimeError::WrongReadbackPhase);
        }
        entry.readback_complete = true;
        Ok(())
    }

    fn take_completed(
        &mut self,
        handle: u32,
    ) -> Result<BallotCiphertextReadbackEntry, BallotValidityRuntimeError> {
        let entry = self.entry(handle)?;
        if !entry.readback_complete || entry.next_chunk_index != entry.descriptor_chunk_count {
            return Err(BallotValidityRuntimeError::WrongReadbackPhase);
        }
        self.active
            .take()
            .map(|(_, entry)| entry)
            .ok_or(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }

    fn discard(&mut self, handle: u32) -> Result<(), BallotValidityRuntimeError> {
        self.entry(handle)?;
        self.active = None;
        Ok(())
    }
}

thread_local! {
    static BALLOT_CIPHERTEXT_READBACK_REGISTRY: RefCell<BallotCiphertextReadbackRegistry> =
        RefCell::new(BallotCiphertextReadbackRegistry::default());
}

struct BallotValidityVerificationPreparation {
    selected_suite_handle: u32,
    accepted_setup_authority_handle: VerifiedAcceptedSetupAuthorityHandle,
    board_source: VerifiedBoardApplicationSource,
    payload: VerifiedBallotPackageApplicationPayload,
    ciphertext_decoder: BallotValidityCiphertextStreamDecoder,
}

#[derive(Default)]
struct BallotValidityVerificationPreparationRegistry {
    active: Option<(u32, BallotValidityVerificationPreparation)>,
    next_handle: u32,
}

impl BallotValidityVerificationPreparationRegistry {
    fn retain(
        &mut self,
        preparation: BallotValidityVerificationPreparation,
    ) -> Result<u32, BallotValidityRuntimeError> {
        if self.active.is_some() {
            return Err(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ));
        }
        let handle = if self.next_handle == 0 {
            1
        } else {
            self.next_handle
        };
        self.next_handle = handle.checked_add(1).filter(|next| *next != 0).ok_or(
            BallotValidityRuntimeError::Runtime(CommonProofRuntimeError::AllocationLimitExceeded),
        )?;
        self.active = Some((handle, preparation));
        Ok(handle)
    }

    fn active_mut(
        &mut self,
        handle: u32,
    ) -> Result<&mut BallotValidityVerificationPreparation, BallotValidityRuntimeError> {
        self.active
            .as_mut()
            .filter(|(active_handle, _)| *active_handle == handle)
            .map(|(_, preparation)| preparation)
            .ok_or(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<BallotValidityVerificationPreparation, BallotValidityRuntimeError> {
        if self
            .active
            .as_ref()
            .map(|(active_handle, _)| *active_handle)
            != Some(handle)
        {
            return Err(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ));
        }
        self.active
            .take()
            .map(|(_, preparation)| preparation)
            .ok_or(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }
}

struct BallotValidityVerificationTerminalSource {
    protocol_version: u16,
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    roster_hash: [u8; 64],
    producer_roster_position: u16,
    ballot_package_object_hash: [u8; 64],
    verified_setup_source_hash: [u8; 64],
    ciphertext_descriptor: StreamDescriptor,
    proof_descriptor: StreamDescriptor,
    verification_binding_hash: [u8; 64],
    proof_application_slot_hash: [u8; 64],
    canonical_proof_application_binding_hash: [u8; 64],
    application_statement_hash: [u8; 64],
    proof_header_hash: [u8; 64],
    relation_plan_hash: [u8; 64],
    relation_plan_variant_hash: [u8; 64],
    ciphertext_catalog: Vec<VerifiedBallotCiphertextPolynomial>,
}

#[derive(Default)]
struct BallotValidityVerificationTerminalRegistry {
    active: Option<(u32, BallotValidityVerificationTerminalSource)>,
    next_handle: u32,
}

impl BallotValidityVerificationTerminalRegistry {
    fn retain(
        &mut self,
        source: BallotValidityVerificationTerminalSource,
    ) -> Result<u32, BallotValidityRuntimeError> {
        if self.active.is_some() {
            return Err(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::AllocationLimitExceeded,
            ));
        }
        let handle = if self.next_handle == 0 {
            1
        } else {
            self.next_handle
        };
        self.next_handle = handle.checked_add(1).filter(|next| *next != 0).ok_or(
            BallotValidityRuntimeError::Runtime(CommonProofRuntimeError::AllocationLimitExceeded),
        )?;
        self.active = Some((handle, source));
        Ok(handle)
    }

    fn take(
        &mut self,
        handle: u32,
    ) -> Result<BallotValidityVerificationTerminalSource, BallotValidityRuntimeError> {
        if self
            .active
            .as_ref()
            .map(|(active_handle, _)| *active_handle)
            != Some(handle)
        {
            return Err(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ));
        }
        self.active
            .take()
            .map(|(_, source)| source)
            .ok_or(BallotValidityRuntimeError::Runtime(
                CommonProofRuntimeError::UnknownOrStaleHandle,
            ))
    }

    fn restore(
        &mut self,
        handle: u32,
        source: BallotValidityVerificationTerminalSource,
    ) -> Result<(), CommonProofRuntimeError> {
        if handle == 0 || self.active.is_some() {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        self.active = Some((handle, source));
        Ok(())
    }
}

type AuthenticatedBallotCiphertextCatalogEntry = (u16, u16, u16, u64, Arc<[u64]>);

/// One authenticated full-level RNS polynomial from a positively verified
/// ballot package. Coefficients are shared immutably with the verifier
/// material until the evaluator aggregation consumes the ballot output.
pub(crate) struct VerifiedBallotCiphertextPolynomial {
    ciphertext_ordinal: u16,
    component_ordinal: u16,
    data_modulus_index: u16,
    modulus: u64,
    coefficients: Arc<[u64]>,
}

impl VerifiedBallotCiphertextPolynomial {
    fn from_authenticated_catalog_entry(
        ciphertext_ordinal: u16,
        component_ordinal: u16,
        data_modulus_index: u16,
        modulus: u64,
        coefficients: Arc<[u64]>,
    ) -> Self {
        Self {
            ciphertext_ordinal,
            component_ordinal,
            data_modulus_index,
            modulus,
            coefficients,
        }
    }

    pub(crate) const fn ciphertext_ordinal(&self) -> u16 {
        self.ciphertext_ordinal
    }

    pub(crate) const fn component_ordinal(&self) -> u16 {
        self.component_ordinal
    }

    pub(crate) const fn data_modulus_index(&self) -> u16 {
        self.data_modulus_index
    }

    pub(crate) const fn modulus(&self) -> u64 {
        self.modulus
    }

    pub(crate) fn coefficients(&self) -> &[u64] {
        &self.coefficients
    }
}

impl Drop for VerifiedBallotCiphertextPolynomial {
    fn drop(&mut self) {
        if let Some(coefficients) = Arc::get_mut(&mut self.coefficients) {
            coefficients.zeroize();
        }
    }
}

fn verified_ciphertext_catalog_from_authenticated(
    authenticated_catalog: impl IntoIterator<Item = AuthenticatedBallotCiphertextCatalogEntry>,
) -> Vec<VerifiedBallotCiphertextPolynomial> {
    authenticated_catalog
        .into_iter()
        .map(
            |(ciphertext_ordinal, component_ordinal, data_modulus_index, modulus, coefficients)| {
                VerifiedBallotCiphertextPolynomial::from_authenticated_catalog_entry(
                    ciphertext_ordinal,
                    component_ordinal,
                    data_modulus_index,
                    modulus,
                    coefficients,
                )
            },
        )
        .collect()
}

enum VerifiedBallotValidityEvidence {
    CommonProof {
        _capability: Box<ConsumedVerifiedCommonProofCapability>,
    },
    #[cfg(test)]
    TestMinted,
}

/// One-shot positive ballot-validity output. No transported verdict or status
/// field can construct this value. Production construction owns the consumed
/// generic verifier authority and the board/setup-derived ciphertext catalog;
/// unit tests may mint the same positive type only through the private registry.
pub(crate) struct VerifiedBallotValidityOutput {
    _evidence: VerifiedBallotValidityEvidence,
    protocol_version: u16,
    suite_identifier: [u8; 64],
    ceremony_context_hash: [u8; 64],
    action_context_hash: [u8; 64],
    roster_hash: [u8; 64],
    producer_roster_position: u16,
    ballot_package_object_hash: [u8; 64],
    verified_setup_source_hash: [u8; 64],
    ciphertext_descriptor: StreamDescriptor,
    ciphertext_catalog: Vec<VerifiedBallotCiphertextPolynomial>,
}

impl VerifiedBallotValidityOutput {
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retain_test_minted(
        protocol_version: u16,
        suite_identifier: [u8; 64],
        ceremony_context_hash: [u8; 64],
        action_context_hash: [u8; 64],
        roster_hash: [u8; 64],
        producer_roster_position: u16,
        ballot_package_object_hash: [u8; 64],
        verified_setup_source_hash: [u8; 64],
        authenticated_catalog: impl IntoIterator<Item = AuthenticatedBallotCiphertextCatalogEntry>,
    ) -> Result<u32, CommonProofRuntimeError> {
        let authenticated_catalog = authenticated_catalog.into_iter().collect::<Vec<_>>();
        if protocol_version != FOUNDATION_PROFILE.protocol_version
            || suite_identifier != selected_suite_capability_for_tests().suite_identifier()
            || producer_roster_position >= FOUNDATION_PROFILE.participant_count
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        let ciphertext_descriptor =
            derive_test_minted_ballot_ciphertext_descriptor(&authenticated_catalog)
                .map_err(|_| CommonProofRuntimeError::WrongVerificationBinding)?;
        let ciphertext_catalog =
            verified_ciphertext_catalog_from_authenticated(authenticated_catalog);
        let reservation = VERIFIED_BALLOT_VALIDITY_OUTPUT_REGISTRY
            .with(|registry| registry.borrow_mut().reserve())?;
        Ok(VERIFIED_BALLOT_VALIDITY_OUTPUT_REGISTRY.with(|registry| {
            registry.borrow_mut().commit_preflighted(
                reservation,
                Self {
                    _evidence: VerifiedBallotValidityEvidence::TestMinted,
                    protocol_version,
                    suite_identifier,
                    ceremony_context_hash,
                    action_context_hash,
                    roster_hash,
                    producer_roster_position,
                    ballot_package_object_hash,
                    verified_setup_source_hash,
                    ciphertext_descriptor,
                    ciphertext_catalog,
                },
            )
        }))
    }

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

    pub(crate) const fn producer_roster_position(&self) -> u16 {
        self.producer_roster_position
    }

    pub(crate) const fn ballot_package_object_hash(&self) -> [u8; 64] {
        self.ballot_package_object_hash
    }

    pub(crate) const fn verified_setup_source_hash(&self) -> [u8; 64] {
        self.verified_setup_source_hash
    }

    pub(crate) const fn ciphertext_descriptor(&self) -> &StreamDescriptor {
        &self.ciphertext_descriptor
    }

    pub(crate) fn ciphertext_catalog(&self) -> &[VerifiedBallotCiphertextPolynomial] {
        &self.ciphertext_catalog
    }
}

#[cfg(test)]
fn derive_test_minted_ballot_ciphertext_descriptor(
    authenticated_catalog: &[AuthenticatedBallotCiphertextCatalogEntry],
) -> Result<StreamDescriptor, RefusalReason> {
    const CIPHERTEXT_COMPONENT_COUNT: usize = 2;

    let data_modulus_count = DATA_PRIMES.len();
    let polynomials_per_ciphertext = CIPHERTEXT_COMPONENT_COUNT
        .checked_mul(data_modulus_count)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let expected_polynomial_count = PAIR_CHARACTER_CIPHERTEXT_COUNT
        .checked_mul(polynomials_per_ciphertext)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    if authenticated_catalog.len() != expected_polynomial_count {
        return Err(RefusalReason::WrongTypeOrLength);
    }
    for (polynomial_ordinal, entry) in authenticated_catalog.iter().enumerate() {
        let expected_ciphertext_ordinal = polynomial_ordinal / polynomials_per_ciphertext;
        let expected_component_ordinal =
            (polynomial_ordinal % polynomials_per_ciphertext) / data_modulus_count;
        let expected_data_modulus_index = polynomial_ordinal % data_modulus_count;
        let expected_modulus = DATA_PRIMES[expected_data_modulus_index];
        if usize::from(entry.0) != expected_ciphertext_ordinal
            || usize::from(entry.1) != expected_component_ordinal
            || usize::from(entry.2) != expected_data_modulus_index
            || entry.3 != expected_modulus
            || entry.4.len() != POLYNOMIAL_DEGREE
            || entry
                .4
                .iter()
                .any(|coefficient| *coefficient >= expected_modulus)
        {
            return Err(RefusalReason::WrongTypeOrLength);
        }
    }

    let bytes_per_flattened_component =
        DATA_PRIMES
            .iter()
            .try_fold(0_u64, |total, modulus| -> Result<u64, RefusalReason> {
                let polynomial_byte_length = u64::try_from(POLYNOMIAL_DEGREE)
                    .ok()
                    .and_then(|degree| {
                        u64::try_from(canonical_modulus_byte_length(*modulus))
                            .ok()
                            .and_then(|width| degree.checked_mul(width))
                    })
                    .ok_or(RefusalReason::OutsideSupportedProfile)?;
                total
                    .checked_add(polynomial_byte_length)
                    .ok_or(RefusalReason::OutsideSupportedProfile)
            })?;
    let flattened_component_count = PAIR_CHARACTER_CIPHERTEXT_COUNT
        .checked_mul(CIPHERTEXT_COMPONENT_COUNT)
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let total_byte_length = u64::try_from(flattened_component_count)
        .ok()
        .and_then(|count| count.checked_mul(bytes_per_flattened_component))
        .and_then(|coefficient_bytes| coefficient_bytes.checked_add(4))
        .ok_or(RefusalReason::OutsideSupportedProfile)?;
    let mut writer =
        CanonicalStreamWriter::new(CanonicalStreamDomain::BallotCiphertext, total_byte_length)?;
    let mut pending_chunk = Vec::with_capacity(FOUNDATION_PROFILE.stream_chunk_byte_length);
    let mut next_chunk_index = 0_usize;
    let level =
        u16::try_from(DATA_PRIMES.len() - 1).map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    let component_count = u16::try_from(flattened_component_count)
        .map_err(|_| RefusalReason::OutsideSupportedProfile)?;
    absorb_test_minted_ballot_ciphertext_bytes(
        &mut writer,
        &mut pending_chunk,
        &mut next_chunk_index,
        &level.to_le_bytes(),
    )?;
    absorb_test_minted_ballot_ciphertext_bytes(
        &mut writer,
        &mut pending_chunk,
        &mut next_chunk_index,
        &component_count.to_le_bytes(),
    )?;
    for (_, _, _, modulus, coefficients) in authenticated_catalog {
        let residue_byte_length = canonical_modulus_byte_length(*modulus);
        for coefficient in coefficients.iter().copied() {
            absorb_test_minted_ballot_ciphertext_bytes(
                &mut writer,
                &mut pending_chunk,
                &mut next_chunk_index,
                &coefficient.to_le_bytes()[..residue_byte_length],
            )?;
        }
    }
    if !pending_chunk.is_empty() {
        writer.absorb_chunk(next_chunk_index, &pending_chunk)?;
        pending_chunk.zeroize();
    }
    writer.finish()
}

#[cfg(test)]
fn absorb_test_minted_ballot_ciphertext_bytes(
    writer: &mut CanonicalStreamWriter,
    pending_chunk: &mut Vec<u8>,
    next_chunk_index: &mut usize,
    mut bytes: &[u8],
) -> Result<(), RefusalReason> {
    while !bytes.is_empty() {
        let remaining_capacity = FOUNDATION_PROFILE
            .stream_chunk_byte_length
            .checked_sub(pending_chunk.len())
            .ok_or(RefusalReason::OutsideSupportedProfile)?;
        let copied = remaining_capacity.min(bytes.len());
        pending_chunk.extend_from_slice(&bytes[..copied]);
        bytes = &bytes[copied..];
        if pending_chunk.len() == FOUNDATION_PROFILE.stream_chunk_byte_length {
            writer.absorb_chunk(*next_chunk_index, pending_chunk)?;
            pending_chunk.zeroize();
            pending_chunk.clear();
            *next_chunk_index = next_chunk_index
                .checked_add(1)
                .ok_or(RefusalReason::OutsideSupportedProfile)?;
        }
    }
    Ok(())
}

#[derive(Default)]
struct VerifiedBallotValidityOutputRegistry {
    outputs: BTreeMap<u32, VerifiedBallotValidityOutput>,
    reserved_handle: Option<u32>,
    next_handle: u32,
}

#[derive(Clone, Copy)]
struct VerifiedBallotValidityOutputReservation {
    handle: u32,
}

impl VerifiedBallotValidityOutputRegistry {
    fn reserve(
        &mut self,
    ) -> Result<VerifiedBallotValidityOutputReservation, CommonProofRuntimeError> {
        if self.outputs.len() + usize::from(self.reserved_handle.is_some())
            >= MAXIMUM_VERIFIED_BALLOT_OUTPUT_COUNT
            || self.reserved_handle.is_some()
        {
            return Err(CommonProofRuntimeError::AllocationLimitExceeded);
        }
        let handle = if self.next_handle == 0 {
            1
        } else {
            self.next_handle
        };
        self.next_handle = handle
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(CommonProofRuntimeError::AllocationLimitExceeded)?;
        self.reserved_handle = Some(handle);
        Ok(VerifiedBallotValidityOutputReservation { handle })
    }

    /// Commits after exact-family preflight while the destination reservation
    /// remains exclusively owned. The generic verifier is consumed only once
    /// this operation has no fallible branch left.
    fn commit_preflighted(
        &mut self,
        reservation: VerifiedBallotValidityOutputReservation,
        output: VerifiedBallotValidityOutput,
    ) -> u32 {
        assert_eq!(
            self.reserved_handle,
            Some(reservation.handle),
            "preflighted ballot-output reservation must remain exclusively retained",
        );
        assert!(
            !self.outputs.contains_key(&reservation.handle),
            "preflighted ballot-output handle must remain vacant",
        );
        self.reserved_handle = None;
        self.outputs.insert(reservation.handle, output);
        reservation.handle
    }

    fn release_reservation(
        &mut self,
        reservation: VerifiedBallotValidityOutputReservation,
    ) -> Result<(), CommonProofRuntimeError> {
        if self.reserved_handle != Some(reservation.handle) {
            return Err(CommonProofRuntimeError::UnknownOrStaleHandle);
        }
        self.reserved_handle = None;
        Ok(())
    }

    fn consume(
        &mut self,
        handle: u32,
    ) -> Result<VerifiedBallotValidityOutput, CommonProofRuntimeError> {
        self.outputs
            .remove(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)
    }
}

thread_local! {
    static BALLOT_VALIDITY_VERIFICATION_PREPARATION_REGISTRY:
        RefCell<BallotValidityVerificationPreparationRegistry> =
        RefCell::new(BallotValidityVerificationPreparationRegistry::default());
    static BALLOT_VALIDITY_VERIFICATION_TERMINAL_REGISTRY:
        RefCell<BallotValidityVerificationTerminalRegistry> =
        RefCell::new(BallotValidityVerificationTerminalRegistry::default());
    static VERIFIED_BALLOT_VALIDITY_OUTPUT_REGISTRY:
        RefCell<VerifiedBallotValidityOutputRegistry> =
        RefCell::new(VerifiedBallotValidityOutputRegistry::default());
}

pub(crate) fn consume_verified_ballot_validity_output(
    handle: u32,
) -> Result<VerifiedBallotValidityOutput, CommonProofRuntimeError> {
    VERIFIED_BALLOT_VALIDITY_OUTPUT_REGISTRY.with(|registry| registry.borrow_mut().consume(handle))
}

/// Borrows one live positive output for an atomic downstream preflight. The
/// caller cannot retain the reference or manufacture a replacement handle;
/// the separate consuming operation remains the only ownership transfer.
pub(crate) fn with_verified_ballot_validity_output<Output>(
    handle: u32,
    inspect: impl FnOnce(&VerifiedBallotValidityOutput) -> Result<Output, CommonProofRuntimeError>,
) -> Result<Output, CommonProofRuntimeError> {
    VERIFIED_BALLOT_VALIDITY_OUTPUT_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let output = registry
            .outputs
            .get(&handle)
            .ok_or(CommonProofRuntimeError::UnknownOrStaleHandle)?;
        inspect(output)
    })
}

fn accepted_setup_binding_for_board_source(
    board_source: &VerifiedBoardApplicationSource,
    authority_handle: &VerifiedAcceptedSetupAuthorityHandle,
) -> Result<(BallotValidityAcceptedSetupBinding, [u8; 64], u16), BallotValidityRuntimeError> {
    let participant_identity = board_source
        .producer_participant_identity()
        .map(|identity| identity.into_bytes())
        .ok_or(BallotValidityRuntimeError::Refusal(
            RefusalReason::WrongContext,
        ))?;
    let board_roster_position =
        board_source
            .producer_roster_position()
            .ok_or(BallotValidityRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ))?;
    let binding = with_verified_accepted_setup_authority(authority_handle, |authority| {
        let participant_release_material = authority
            .participant_release_material(participant_identity)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::ComponentMismatch,
                    "ballot producer is absent from the accepted setup",
                )
            })?;
        if authority.suite_identifier() != board_source.suite_identifier().into_bytes()
            || authority.ceremony_context_hash()
                != board_source.ceremony_context_hash().into_bytes()
            || authority.action_context_hash() != board_source.action_context_hash().into_bytes()
            || authority.roster_hash() != board_source.roster_hash().into_bytes()
            || participant_release_material.roster_position() != board_roster_position
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::ComponentMismatch,
                "ballot board source and accepted setup bindings differ",
            ));
        }
        Ok(BallotValidityAcceptedSetupBinding {
            protocol_version: authority.protocol_version(),
            suite_identifier: authority.suite_identifier(),
            ceremony_context_hash: authority.ceremony_context_hash(),
            action_context_hash: authority.action_context_hash(),
            roster_hash: authority.roster_hash(),
            exact_verified_setup_source_hash: authority.exact_verified_setup_source_hash(),
        })
    })?;
    Ok((binding, participant_identity, board_roster_position))
}

fn resolve_single_verified_ballot_package(
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ballot_package_object_handle: u32,
) -> Result<
    (
        VerifiedBoardApplicationSource,
        VerifiedBallotPackageApplicationPayload,
    ),
    BallotValidityRuntimeError,
> {
    if board_verifier_session_capability.len() != BOARD_VERIFIER_SESSION_CAPABILITY_BYTE_LENGTH {
        return Err(BallotValidityRuntimeError::InvalidInput);
    }
    let mut board_sources = resolve_verified_board_application_sources(
        board_verifier_session_handle,
        board_verifier_session_capability,
        &[ballot_package_object_handle],
    )
    .map_err(BallotValidityRuntimeError::BoardRuntime)?;
    let board_source = board_sources
        .pop()
        .ok_or(BallotValidityRuntimeError::Refusal(
            RefusalReason::MissingPrerequisite,
        ))?;
    if !board_sources.is_empty() {
        return Err(BallotValidityRuntimeError::InvalidInput);
    }
    let payload = board_source
        .ballot_package_payload()
        .map_err(BallotValidityRuntimeError::Refusal)?;
    Ok((board_source, payload))
}

fn begin_ballot_validity_verification(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ballot_package_object_handle: u32,
) -> Result<u32, BallotValidityRuntimeError> {
    let (board_source, payload) = resolve_single_verified_ballot_package(
        board_verifier_session_handle,
        board_verifier_session_capability,
        ballot_package_object_handle,
    )?;
    with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        if selected_suite.protocol_version() == 0
            || selected_suite.suite_identifier() != board_source.suite_identifier().into_bytes()
        {
            return Err(BallotValidityRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        Ok(())
    })
    .map_err(BallotValidityRuntimeError::Runtime)??;
    let accepted_setup_authority_handle =
        VerifiedAcceptedSetupAuthorityHandle::from_identifier(accepted_setup_authority_handle);
    accepted_setup_binding_for_board_source(&board_source, &accepted_setup_authority_handle)?;
    let compilation = selected_ballot_validity_relation_compilation()?;
    let ciphertext_decoder = BallotValidityCiphertextStreamDecoder::new(
        compilation.source_plan(),
        payload.ciphertext_descriptor().clone(),
    )
    .map_err(BallotValidityRuntimeError::Refusal)?;
    BALLOT_VALIDITY_VERIFICATION_PREPARATION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .retain(BallotValidityVerificationPreparation {
                selected_suite_handle,
                accepted_setup_authority_handle,
                board_source,
                payload,
                ciphertext_decoder,
            })
    })
}

fn absorb_ballot_ciphertext_chunk(
    preparation_handle: u32,
    chunk_index: usize,
    chunk_bytes: &[u8],
) -> Result<(), BallotValidityRuntimeError> {
    BALLOT_VALIDITY_VERIFICATION_PREPARATION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .active_mut(preparation_handle)?
            .ciphertext_decoder
            .absorb_chunk(chunk_index, chunk_bytes)
            .into_result()
            .map_err(BallotValidityRuntimeError::Refusal)
    })
}

fn finish_ballot_validity_verification_preparation(
    preparation_handle: u32,
) -> Result<(u32, u32), BallotValidityRuntimeError> {
    let preparation = BALLOT_VALIDITY_VERIFICATION_PREPARATION_REGISTRY
        .with(|registry| registry.borrow_mut().take(preparation_handle))?;
    let authenticated_ciphertext = preparation
        .ciphertext_decoder
        .finish()
        .into_result()
        .map_err(BallotValidityRuntimeError::Refusal)?;
    let compilation = selected_ballot_validity_relation_compilation()?;
    let (accepted_setup_binding, producer_identity, producer_roster_position) =
        accepted_setup_binding_for_board_source(
            &preparation.board_source,
            &preparation.accepted_setup_authority_handle,
        )?;
    let public_material = BallotValidityBoundPublicMaterial::from_verified_accepted_setup(
        compilation.source_plan(),
        &preparation.accepted_setup_authority_handle,
        accepted_setup_binding,
        authenticated_ciphertext,
    )?;
    let ciphertext_catalog = verified_ciphertext_catalog_from_authenticated(
        public_material.authenticated_ciphertext_catalog()?,
    );
    let canonical_application_statement_bytes = canonical_selected_ballot_validity_statement(
        accepted_setup_binding.protocol_version,
        accepted_setup_binding.suite_identifier,
        accepted_setup_binding.ceremony_context_hash,
        accepted_setup_binding.action_context_hash,
        accepted_setup_binding.roster_hash,
        producer_identity,
        preparation.board_source.producer_sequence(),
        accepted_setup_binding.exact_verified_setup_source_hash,
        public_material.ballot_ciphertext_digest(),
    )
    .map_err(|_| BallotValidityRuntimeError::InvalidInput)?;
    let application_slot = ProofApplicationSlot::new(
        Hash512::from_bytes(accepted_setup_binding.suite_identifier),
        Hash512::from_bytes(accepted_setup_binding.ceremony_context_hash),
        Hash512::from_bytes(accepted_setup_binding.action_context_hash),
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        Some(producer_roster_position),
        None,
        Some(preparation.board_source.producer_sequence()),
    )?;
    let proof_header = ProofObjectHeader::from_canonical_application_statement(
        canonical_application_statement_bytes.clone(),
        &CanonicalDecodeLimits::default(),
    )?;
    let proof_header_hash = proof_header.proof_header_hash()?;
    let proof_application_binding = ProofApplicationBinding::new(
        application_slot,
        proof_header_hash,
        preparation.payload.proof_descriptor().clone(),
    )?;
    let canonical_proof_application_binding_hash = hash_framed_parts_512(
        CANONICAL_PROOF_APPLICATION_BINDING_HASH_DOMAIN,
        &[&proof_application_binding.encode()?],
    );
    let variant = compilation.relation_plan().select_variant(None, None)?;
    let limits = selected_proof_runtime_limits(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        &canonical_application_statement_bytes,
        variant,
    )?;
    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(BallotValidityRuntimeError::Relation(
        RelationPlanError::InvalidDomain,
    ))?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        compilation.relation_plan(),
        &relation_context,
        None,
        None,
    )?;
    let relation_plan_hash = relation_plan.relation_plan_hash();
    let relation_plan_variant_hash = relation_plan.relation_plan_variant_hash();
    let evaluator = BallotValidityVerifiedColumnEvaluator::new(
        &compilation,
        accepted_setup_binding.exact_verified_setup_source_hash,
        public_material.ballot_ciphertext_digest(),
        public_material,
    )?;
    let statement_source =
        VerifiedCommonProofStatementSource::from_exact_family_verified_board_source(
            preparation.board_source.clone(),
            accepted_setup_binding.protocol_version,
            canonical_application_statement_bytes.clone(),
            proof_application_binding.clone(),
            relation_plan,
            limits,
        )?;
    let verification_binding_hash = statement_source.verification_binding_hash();
    let terminal_source = BallotValidityVerificationTerminalSource {
        protocol_version: accepted_setup_binding.protocol_version,
        suite_identifier: accepted_setup_binding.suite_identifier,
        ceremony_context_hash: accepted_setup_binding.ceremony_context_hash,
        action_context_hash: accepted_setup_binding.action_context_hash,
        roster_hash: accepted_setup_binding.roster_hash,
        producer_roster_position,
        ballot_package_object_hash: preparation.board_source.object_hash().into_bytes(),
        verified_setup_source_hash: accepted_setup_binding.exact_verified_setup_source_hash,
        ciphertext_descriptor: preparation.payload.ciphertext_descriptor().clone(),
        proof_descriptor: preparation.payload.proof_descriptor().clone(),
        verification_binding_hash,
        proof_application_slot_hash: application_slot.hash()?.into_bytes(),
        canonical_proof_application_binding_hash,
        application_statement_hash: verified_application_statement_hash(
            accepted_setup_binding.protocol_version,
            accepted_setup_binding.suite_identifier,
            ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
            &canonical_application_statement_bytes,
        ),
        proof_header_hash: proof_header_hash.into_bytes(),
        relation_plan_hash,
        relation_plan_variant_hash,
        ciphertext_catalog,
    };
    let terminal_source_handle = BALLOT_VALIDITY_VERIFICATION_TERMINAL_REGISTRY
        .with(|registry| registry.borrow_mut().retain(terminal_source))?;
    let selected_suite_handle = CommonProofSelectedSuiteCapabilityHandle::from_identifier(
        preparation.selected_suite_handle,
    );
    let adapter_result =
        retain_common_proof_verification_family_adapter_from_upstream(move |upstream_inputs| {
            upstream_inputs.prepare_proof_created_tree_family_verification(
                &selected_suite_handle,
                statement_source,
                Box::new(evaluator),
            )
        });
    match adapter_result {
        Ok(adapter_handle) => Ok((adapter_handle, terminal_source_handle)),
        Err(error) => {
            BALLOT_VALIDITY_VERIFICATION_TERMINAL_REGISTRY
                .with(|registry| registry.borrow_mut().take(terminal_source_handle))?;
            Err(BallotValidityRuntimeError::Runtime(error))
        }
    }
}

impl BallotValidityVerificationTerminalSource {
    fn preflight_verified_common_proof(
        &self,
        verified_common_proof: BorrowedVerifiedCommonProofCapability<'_>,
    ) -> Result<(), CommonProofRuntimeError> {
        if verified_common_proof.protocol_version() != self.protocol_version
            || verified_common_proof.suite_identifier() != self.suite_identifier
            || verified_common_proof.ceremony_context_hash() != self.ceremony_context_hash
            || verified_common_proof.action_context_hash() != self.action_context_hash
            || verified_common_proof.board_object_hash() != self.ballot_package_object_hash
            || verified_common_proof.verification_binding_hash() != self.verification_binding_hash
            || verified_common_proof.proof_application_slot_hash()
                != self.proof_application_slot_hash
            || verified_common_proof.canonical_proof_application_binding_hash()
                != self.canonical_proof_application_binding_hash
            || verified_common_proof.application_statement_schema_identifier()
                != ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER
            || verified_common_proof.application_statement_hash() != self.application_statement_hash
            || verified_common_proof.proof_header_hash() != self.proof_header_hash
            || verified_common_proof.proof_stream_domain()
                != CanonicalStreamDomain::BallotValidityProof
            || verified_common_proof.proof_stream_full_object_digest()
                != self.proof_descriptor.full_object_digest.into_bytes()
            || verified_common_proof.proof_byte_length() != self.proof_descriptor.total_byte_length
            || verified_common_proof.relation_plan_hash() != self.relation_plan_hash
            || verified_common_proof.relation_plan_variant_hash() != self.relation_plan_variant_hash
            || verified_common_proof.schedule_position().is_some()
            || verified_common_proof.top_count().is_some()
        {
            return Err(CommonProofRuntimeError::WrongVerificationBinding);
        }
        Ok(())
    }

    fn complete_preflighted_verified_common_proof(
        self,
        verified_common_proof: ConsumedVerifiedCommonProofCapability,
    ) -> VerifiedBallotValidityOutput {
        debug_assert!(
            self.preflight_verified_common_proof(verified_common_proof.borrowed())
                .is_ok(),
            "consumed ballot proof must match its completed exact-family preflight",
        );
        VerifiedBallotValidityOutput {
            _evidence: VerifiedBallotValidityEvidence::CommonProof {
                _capability: Box::new(verified_common_proof),
            },
            protocol_version: self.protocol_version,
            suite_identifier: self.suite_identifier,
            ceremony_context_hash: self.ceremony_context_hash,
            action_context_hash: self.action_context_hash,
            roster_hash: self.roster_hash,
            producer_roster_position: self.producer_roster_position,
            ballot_package_object_hash: self.ballot_package_object_hash,
            verified_setup_source_hash: self.verified_setup_source_hash,
            ciphertext_descriptor: self.ciphertext_descriptor,
            ciphertext_catalog: self.ciphertext_catalog,
        }
    }
}

fn finish_ballot_validity_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
) -> Result<u32, CommonProofRuntimeError> {
    let terminal_source = BALLOT_VALIDITY_VERIFICATION_TERMINAL_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(terminal_source_handle)
            .map_err(|error| match error {
                BallotValidityRuntimeError::Runtime(error) => error,
                _ => CommonProofRuntimeError::WrongVerificationBinding,
            })
    })?;
    let output_reservation = match VERIFIED_BALLOT_VALIDITY_OUTPUT_REGISTRY
        .with(|registry| registry.borrow_mut().reserve())
    {
        Ok(handle) => handle,
        Err(error) => {
            BALLOT_VALIDITY_VERIFICATION_TERMINAL_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .restore(terminal_source_handle, terminal_source)
            })?;
            return Err(error);
        }
    };
    let terminal_source_cell = RefCell::new(Some(terminal_source));
    let result = super::preflight_and_consume_verified_common_proof_with_family_terminal(
        &super::VerifiedCommonProofCapabilityHandle::from_identifier(verified_common_proof_handle),
        |verified_common_proof| {
            let terminal_source = terminal_source_cell.borrow();
            let terminal_source = terminal_source
                .as_ref()
                .ok_or(CommonProofRuntimeError::WrongVerificationBinding)?;
            terminal_source.preflight_verified_common_proof(verified_common_proof)
        },
        |verified_common_proof, ()| {
            let terminal_source = terminal_source_cell
                .borrow_mut()
                .take()
                .expect("ballot terminal preflight retained the exact source");
            let output =
                terminal_source.complete_preflighted_verified_common_proof(verified_common_proof);
            VERIFIED_BALLOT_VALIDITY_OUTPUT_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .commit_preflighted(output_reservation, output)
            })
        },
    );
    if result.is_err() {
        let reservation_release_result =
            VERIFIED_BALLOT_VALIDITY_OUTPUT_REGISTRY.with(|registry| {
                registry
                    .borrow_mut()
                    .release_reservation(output_reservation)
            });
        let terminal_restore_result =
            if let Some(terminal_source) = terminal_source_cell.into_inner() {
                BALLOT_VALIDITY_VERIFICATION_TERMINAL_REGISTRY.with(|registry| {
                    registry
                        .borrow_mut()
                        .restore(terminal_source_handle, terminal_source)
                })
            } else {
                Ok(())
            };
        reservation_release_result?;
        terminal_restore_result?;
    }
    result
}

struct PreparedBallotValidityGeneration {
    generation_family_adapter_handle: u32,
    ciphertext_readback_handle: u32,
}

#[derive(Clone, Copy)]
enum BallotValidityGenerationMode {
    Fresh,
    Resume,
}

#[allow(clippy::too_many_arguments)]
fn prepare_ballot_validity_generation(
    selected_suite_handle: u32,
    action_randomness_handle: u32,
    accepted_setup_authority_handle: u32,
    producer_sequence: u64,
    scores: Zeroizing<[u64; BALLOT_SCORE_COUNT]>,
    encryption_attempt_identifier: Zeroizing<[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]>,
    proof_attempt_nonce: Zeroizing<[u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH]>,
    checkpoint_lineage_identifier: [u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH],
    generation_mode: BallotValidityGenerationMode,
) -> Result<PreparedBallotValidityGeneration, BallotValidityRuntimeError> {
    if checkpoint_lineage_identifier == [0_u8; ATTEMPT_IDENTIFIER_BYTE_LENGTH] {
        return Err(BallotValidityRuntimeError::InvalidInput);
    }
    let compilation = selected_ballot_validity_relation_compilation()?;
    let relation_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .ok_or(BallotValidityRuntimeError::Relation(
        RelationPlanError::InvalidDomain,
    ))?;
    let variant = compilation.relation_plan().select_variant(None, None)?;
    let action_private_randomness =
        retain_action_private_randomness_for_exact_family(action_randomness_handle)
            .map_err(BallotValidityRuntimeError::ActionRandomness)?;
    let accepted_setup_authority_handle =
        VerifiedAcceptedSetupAuthorityHandle::from_identifier(accepted_setup_authority_handle);
    let application_statement_context =
        with_verified_accepted_setup_authority(&accepted_setup_authority_handle, |authority| {
            Ok(SelectedApplicationStatementContext::new(
                authority.protocol_version(),
                authority.suite_identifier(),
                None,
                None,
            ))
        })?;
    let attempt = with_common_proof_selected_suite(selected_suite_handle, |selected_suite| {
        BallotValidityPreparedProofAttempt::prepare_selected(
            &compilation,
            selected_suite,
            action_private_randomness,
            &accepted_setup_authority_handle,
            producer_sequence,
            scores.as_ref(),
            encryption_attempt_identifier,
            proof_attempt_nonce,
        )
    })
    .map_err(BallotValidityRuntimeError::Runtime)??;
    let canonical_application_statement_bytes = attempt
        .canonical_application_statement_bytes()
        .to_vec()
        .into_boxed_slice();
    let ballot_package_statement = decode_selected_ballot_validity_statement(
        &canonical_application_statement_bytes,
        application_statement_context,
    )
    .map_err(|_| BallotValidityRuntimeError::InvalidInput)?;
    let limits = selected_proof_runtime_limits(
        ProofApplicationSlotCeilings::BALLOT_VALIDITY_STATEMENT_SCHEMA_IDENTIFIER,
        &canonical_application_statement_bytes,
        variant,
    )?;
    let relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
        compilation.relation_plan(),
        &relation_context,
        None,
        None,
    )?;
    let descriptor = attempt.generated_ciphertext().descriptor().clone();
    let descriptor_total_byte_length = descriptor.total_byte_length;
    let descriptor_chunk_count = descriptor.ordered_chunk_digests.len();
    let descriptor_bytes = descriptor.encode()?.into_boxed_slice();
    let readback = attempt
        .generated_ciphertext()
        .begin_readback(compilation.source_plan())?;
    let generation_family_adapter = match generation_mode {
        BallotValidityGenerationMode::Fresh => {
            let prepared_generation = attempt.prepare_fresh_common_generation(
                &compilation,
                relation_plan,
                limits,
                checkpoint_lineage_identifier,
            )?;
            CommonProofGenerationFamilyAdapter::fresh(prepared_generation)
        }
        BallotValidityGenerationMode::Resume => {
            let checkpoint_schedule_digest = relation_plan.checkpoint_schedule_digest()?;
            let fresh_preparation = attempt.prepare_fresh_common_generation(
                &compilation,
                relation_plan,
                limits,
                checkpoint_lineage_identifier,
            )?;
            let description = CommonProofGenerationFamilyAdapterDescription::new(
                fresh_preparation.application_statement_schema_identifier(),
                fresh_preparation.runtime_binding_hash(),
                fresh_preparation.generation_authorization_hash(),
                fresh_preparation.proof_attempt_lineage_identifier(),
            );
            drop(fresh_preparation);
            let resumed_relation_plan = CommonProofRelationPlanCapability::from_compiled_plan(
                compilation.relation_plan(),
                &relation_context,
                None,
                None,
            )?;
            CommonProofGenerationFamilyAdapter::resume(
                description,
                checkpoint_lineage_identifier,
                checkpoint_schedule_digest,
                Box::new(move |authenticated_continuation| {
                    attempt
                        .prepare_common_generation_with_continuation(
                            &compilation,
                            resumed_relation_plan,
                            limits,
                            authenticated_continuation,
                        )
                        .map_err(resume_preparation_error)
                }),
            )
        }
    };
    let ciphertext_readback_handle = BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        registry.borrow_mut().retain(BallotCiphertextReadbackEntry {
            descriptor,
            descriptor_bytes,
            descriptor_total_byte_length,
            descriptor_chunk_count,
            next_chunk_index: 0,
            readback_complete: false,
            canonical_application_statement_bytes,
            ballot_package_statement,
            readback,
        })
    })?;
    let generation_family_adapter_handle =
        match retain_common_proof_generation_family_adapter(generation_family_adapter) {
            Ok(handle) => handle,
            Err(error) => {
                BALLOT_CIPHERTEXT_READBACK_REGISTRY
                    .with(|registry| registry.borrow_mut().discard(ciphertext_readback_handle))?;
                return Err(BallotValidityRuntimeError::Runtime(error));
            }
        };
    Ok(PreparedBallotValidityGeneration {
        generation_family_adapter_handle,
        ciphertext_readback_handle,
    })
}

fn resume_preparation_error(
    error: BallotValidityGenerationPreparationError,
) -> CommonProofGenerationPreparationError {
    match error {
        BallotValidityGenerationPreparationError::Runtime(error) => {
            CommonProofGenerationPreparationError::Runtime(error)
        }
        BallotValidityGenerationPreparationError::Common(error) => error,
        // The fresh description probe already accepted the family-owned
        // statement, witness, plan, and source adapters. Any later adapter
        // mismatch can therefore only be a disagreement with the
        // authenticated continuation supplied for this resume attempt.
        BallotValidityGenerationPreparationError::Adapter(_) => {
            CommonProofGenerationPreparationError::Runtime(
                CommonProofRuntimeError::WrongVerificationBinding,
            )
        }
    }
}

fn expected_ciphertext_chunk_byte_length(
    entry: &BallotCiphertextReadbackEntry,
    chunk_index: usize,
) -> Result<usize, BallotValidityRuntimeError> {
    if chunk_index >= entry.descriptor_chunk_count {
        return Err(BallotValidityRuntimeError::WrongReadbackPhase);
    }
    let chunk_byte_length = u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .map_err(|_| BallotValidityRuntimeError::InvalidInput)?;
    let chunk_start = u64::try_from(chunk_index)
        .ok()
        .and_then(|index| index.checked_mul(chunk_byte_length))
        .ok_or(BallotValidityRuntimeError::InvalidInput)?;
    let remaining = entry
        .descriptor_total_byte_length
        .checked_sub(chunk_start)
        .ok_or(BallotValidityRuntimeError::WrongReadbackPhase)?;
    usize::try_from(remaining.min(chunk_byte_length))
        .map_err(|_| BallotValidityRuntimeError::InvalidInput)
}

fn read_ciphertext_chunk(
    handle: u32,
    chunk_index: usize,
) -> Result<Vec<u8>, BallotValidityRuntimeError> {
    BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        let mut registry = registry.borrow_mut();
        let entry = registry.entry_mut(handle)?;
        if entry.next_chunk_index != chunk_index {
            return Err(BallotValidityRuntimeError::WrongReadbackPhase);
        }
        let expected_byte_length = expected_ciphertext_chunk_byte_length(entry, chunk_index)?;
        let chunk = entry
            .readback
            .next_chunk()?
            .ok_or(BallotValidityRuntimeError::WrongReadbackPhase)?;
        if chunk.len() != expected_byte_length {
            return Err(BallotValidityRuntimeError::WrongReadbackPhase);
        }
        entry.next_chunk_index = entry
            .next_chunk_index
            .checked_add(1)
            .ok_or(BallotValidityRuntimeError::InvalidInput)?;
        Ok(chunk)
    })
}

fn decode_exact_stream_descriptor(
    canonical_bytes: &[u8],
) -> Result<StreamDescriptor, BallotValidityRuntimeError> {
    if canonical_bytes.is_empty()
        || canonical_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(BallotValidityRuntimeError::Refusal(
            if canonical_bytes.is_empty() {
                RefusalReason::WrongTypeOrLength
            } else {
                RefusalReason::OutsideSupportedProfile
            },
        ));
    }
    let descriptor = StreamDescriptor::decode(canonical_bytes, &CanonicalDecodeLimits::default())?;
    if descriptor.encode()? != canonical_bytes {
        return Err(BallotValidityRuntimeError::Refusal(
            RefusalReason::MalformedEncoding,
        ));
    }
    let maximum_proof_byte_length = u64::try_from(MAXIMUM_COMMON_PROOF_BYTE_LENGTH)
        .map_err(|_| BallotValidityRuntimeError::InvalidInput)?;
    if descriptor.total_byte_length > maximum_proof_byte_length {
        return Err(BallotValidityRuntimeError::Refusal(
            RefusalReason::OutsideSupportedProfile,
        ));
    }
    Ok(descriptor)
}

fn decode_exact_roster(canonical_bytes: &[u8]) -> Result<Roster, BallotValidityRuntimeError> {
    if canonical_bytes.is_empty()
        || canonical_bytes.len() > FOUNDATION_PROFILE.maximum_copied_buffer_byte_length
    {
        return Err(BallotValidityRuntimeError::Refusal(
            if canonical_bytes.is_empty() {
                RefusalReason::WrongTypeOrLength
            } else {
                RefusalReason::OutsideSupportedProfile
            },
        ));
    }
    let roster = Roster::decode(canonical_bytes, &CanonicalDecodeLimits::default())?;
    if roster.encode()? != canonical_bytes {
        return Err(BallotValidityRuntimeError::Refusal(
            RefusalReason::MalformedEncoding,
        ));
    }
    Ok(roster)
}

fn prepare_ballot_package_carrier(
    ciphertext_readback_handle: u32,
    canonical_proof_descriptor_bytes: &[u8],
    canonical_roster_bytes: &[u8],
) -> Result<PreparedSignedCarrierDescription, BallotValidityRuntimeError> {
    let proof_descriptor = decode_exact_stream_descriptor(canonical_proof_descriptor_bytes)?;
    let roster = decode_exact_roster(canonical_roster_bytes)?;
    BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let entry = registry.entry(ciphertext_readback_handle)?;
        if !entry.readback_complete || entry.next_chunk_index != entry.descriptor_chunk_count {
            return Err(BallotValidityRuntimeError::WrongReadbackPhase);
        }
        let statement = entry.ballot_package_statement;
        if statement.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || statement.ballot_ciphertext_full_object_digest()
                != entry.descriptor.full_object_digest.into_bytes()
        {
            return Err(BallotValidityRuntimeError::Refusal(
                RefusalReason::WrongHashOrRoot,
            ));
        }
        let payload = BallotPackagePayload::new(entry.descriptor.clone(), proof_descriptor)?;
        let envelope = ObjectEnvelope {
            suite_id: Hash512::from_bytes(statement.suite_identifier()),
            object_type: FoundationObjectType::BallotPackage,
            ceremony_context_hash: Hash512::from_bytes(statement.ceremony_context_hash()),
            action_context_hash: Hash512::from_bytes(statement.action_context_hash()),
            producer_participant_id: Some(ParticipantIdentity::from_bytes(
                statement.participant_identity(),
            )),
            producer_sequence: statement.producer_sequence(),
            ordered_prerequisite_hashes: vec![Hash512::from_bytes(
                statement.verified_setup_source_hash(),
            )],
            payload_bytes: payload.encode()?,
        };
        retain_prepared_signed_carrier(
            envelope,
            &roster,
            Hash512::from_bytes(statement.roster_hash()),
        )
        .map_err(BallotValidityRuntimeError::Refusal)
    })
}

fn bind_generated_ballot_validity_proof_to_board(
    generated_common_proof_handle: u32,
    ciphertext_readback_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability: &[u8],
    ballot_package_object_handle: u32,
) -> Result<(), BallotValidityRuntimeError> {
    let (board_source, payload) = resolve_single_verified_ballot_package(
        board_verifier_session_handle,
        board_verifier_session_capability,
        ballot_package_object_handle,
    )?;
    BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let entry = registry.entry(ciphertext_readback_handle)?;
        if !entry.readback_complete || entry.next_chunk_index != entry.descriptor_chunk_count {
            return Err(BallotValidityRuntimeError::WrongReadbackPhase);
        }
        if payload.ciphertext_descriptor() != &entry.descriptor {
            return Err(BallotValidityRuntimeError::Refusal(
                RefusalReason::WrongHashOrRoot,
            ));
        }
        let statement = decode_selected_ballot_validity_statement(
            &entry.canonical_application_statement_bytes,
            SelectedApplicationStatementContext::new(
                FOUNDATION_PROFILE.protocol_version,
                board_source.suite_identifier().into_bytes(),
                None,
                None,
            ),
        )
        .map_err(|_| {
            BallotValidityRuntimeError::Runtime(CommonProofRuntimeError::WrongVerificationBinding)
        })?;
        let producer_identity = board_source
            .producer_participant_identity()
            .map(|identity| identity.into_bytes())
            .ok_or(BallotValidityRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ))?;
        if statement.protocol_version() != FOUNDATION_PROFILE.protocol_version
            || statement.suite_identifier() != board_source.suite_identifier().into_bytes()
            || statement.ceremony_context_hash()
                != board_source.ceremony_context_hash().into_bytes()
            || statement.action_context_hash() != board_source.action_context_hash().into_bytes()
            || statement.roster_hash() != board_source.roster_hash().into_bytes()
            || statement.participant_identity() != producer_identity
            || statement.producer_sequence() != board_source.producer_sequence()
            || statement.ballot_ciphertext_full_object_digest()
                != payload
                    .ciphertext_descriptor()
                    .full_object_digest
                    .into_bytes()
        {
            return Err(BallotValidityRuntimeError::Refusal(
                RefusalReason::WrongContext,
            ));
        }
        bind_generated_common_proof_to_verified_board_source(
            generated_common_proof_handle,
            &board_source,
            payload.proof_descriptor(),
            &entry.canonical_application_statement_bytes,
        )
        .map_err(BallotValidityRuntimeError::Runtime)
    })?;
    BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take_completed(ciphertext_readback_handle)
            .map(|_| ())
    })
}

const fn refusal_status(refusal_reason: RefusalReason) -> u32 {
    refusal_reason.canonical_code() as u32
}

fn adapter_error_status(error: BallotValidityAdapterError) -> u32 {
    match error {
        BallotValidityAdapterError::WrongApplication
        | BallotValidityAdapterError::InvalidStatementBinding => {
            refusal_status(RefusalReason::WrongContext)
        }
        BallotValidityAdapterError::InvalidWitness
        | BallotValidityAdapterError::NoWrapBoundViolated => {
            refusal_status(RefusalReason::InvalidArithmeticRelation)
        }
        BallotValidityAdapterError::Stream(refusal_reason) => refusal_status(refusal_reason),
        BallotValidityAdapterError::Foundation(error) => refusal_status(error.refusal_reason),
        BallotValidityAdapterError::Canonical(error) => match error.code {
            CanonicalErrorCode::ComponentMismatch => refusal_status(RefusalReason::WrongContext),
            CanonicalErrorCode::UnsupportedObjectVersion => {
                refusal_status(RefusalReason::UnsupportedVersionOrSuite)
            }
            CanonicalErrorCode::MalformedLength => refusal_status(RefusalReason::WrongTypeOrLength),
            CanonicalErrorCode::DuplicateField
            | CanonicalErrorCode::InvalidEnum
            | CanonicalErrorCode::InvalidHex
            | CanonicalErrorCode::InvalidUtf8
            | CanonicalErrorCode::MalformedMagic
            | CanonicalErrorCode::MalformedVarUint
            | CanonicalErrorCode::NonCanonicalVarUint
            | CanonicalErrorCode::TrailingBytes => refusal_status(RefusalReason::MalformedEncoding),
            CanonicalErrorCode::InvalidProtocolObject => {
                refusal_status(RefusalReason::InvalidArithmeticRelation)
            }
        },
        BallotValidityAdapterError::InvalidPublicMaterial
        | BallotValidityAdapterError::InvalidColumn
        | BallotValidityAdapterError::IntegerOverflow
        | BallotValidityAdapterError::Field(_)
        | BallotValidityAdapterError::Polynomial(_)
        | BallotValidityAdapterError::Relation(_)
        | BallotValidityAdapterError::PrivateCoins(_) => {
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

fn runtime_error_status(error: BallotValidityRuntimeError) -> u32 {
    match error {
        BallotValidityRuntimeError::Adapter(error) => adapter_error_status(error),
        BallotValidityRuntimeError::GenerationPreparation(error) => match error {
            BallotValidityGenerationPreparationError::Adapter(error) => adapter_error_status(error),
            BallotValidityGenerationPreparationError::Runtime(error) => {
                super::runtime_ffi::runtime_error_status(error)
            }
            BallotValidityGenerationPreparationError::Common(_) => {
                refusal_status(RefusalReason::OutsideSupportedProfile)
            }
        },
        BallotValidityRuntimeError::Runtime(error) => {
            super::runtime_ffi::runtime_error_status(error)
        }
        BallotValidityRuntimeError::ActionRandomness(status)
            if status == ACTION_RANDOMNESS_RUNTIME_STALE_HANDLE =>
        {
            refusal_status(RefusalReason::ConsumedState)
        }
        BallotValidityRuntimeError::ActionRandomness(status)
            if status == ACTION_RANDOMNESS_RUNTIME_RESOURCE_LIMIT =>
        {
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        BallotValidityRuntimeError::BoardRuntime(status) => status,
        BallotValidityRuntimeError::Refusal(refusal_reason) => refusal_status(refusal_reason),
        BallotValidityRuntimeError::Schema(error) => refusal_status(error.refusal_reason),
        BallotValidityRuntimeError::Canonical(error) => {
            adapter_error_status(BallotValidityAdapterError::Canonical(error))
        }
        BallotValidityRuntimeError::InvalidInput => {
            refusal_status(RefusalReason::WrongTypeOrLength)
        }
        BallotValidityRuntimeError::WrongReadbackPhase => {
            refusal_status(RefusalReason::ConsumedState)
        }
        BallotValidityRuntimeError::Accounting(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        BallotValidityRuntimeError::Relation(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        BallotValidityRuntimeError::RelationCapability(error) => {
            let _ = error;
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
        BallotValidityRuntimeError::ActionRandomness(_) => {
            refusal_status(RefusalReason::OutsideSupportedProfile)
        }
    }
}

unsafe fn fixed_input<const BYTE_LENGTH: usize>(
    pointer: *const u8,
) -> Result<[u8; BYTE_LENGTH], BallotValidityRuntimeError> {
    if pointer.is_null() {
        return Err(BallotValidityRuntimeError::InvalidInput);
    }
    let bytes = unsafe { slice::from_raw_parts(pointer, BYTE_LENGTH) };
    bytes
        .try_into()
        .map_err(|_| BallotValidityRuntimeError::InvalidInput)
}

unsafe fn write_status(status_pointer: *mut u32, status: u32) {
    if !status_pointer.is_null() {
        unsafe { status_pointer.write(status) };
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn prepare_generation_from_ffi_inputs(
    selected_suite_handle: u32,
    action_randomness_handle: u32,
    accepted_setup_authority_handle: u32,
    producer_sequence: u64,
    scores_pointer: *const u8,
    scores_byte_length: usize,
    encryption_attempt_identifier_pointer: *const u8,
    proof_attempt_nonce_pointer: *const u8,
    checkpoint_lineage_identifier_pointer: *const u8,
    ciphertext_readback_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
    generation_mode: BallotValidityGenerationMode,
) -> u32 {
    let result = (|| {
        if scores_pointer.is_null()
            || scores_byte_length != BALLOT_SCORE_INPUT_BYTE_LENGTH
            || ciphertext_readback_handle_output_pointer.is_null()
        {
            return Err(BallotValidityRuntimeError::InvalidInput);
        }
        let score_bytes = unsafe { slice::from_raw_parts(scores_pointer, scores_byte_length) };
        let mut scores = Zeroizing::new([0_u64; BALLOT_SCORE_COUNT]);
        for (score, encoded_score) in scores.iter_mut().zip(score_bytes.chunks_exact(8)) {
            *score = u64::from_le_bytes(
                encoded_score
                    .try_into()
                    .map_err(|_| BallotValidityRuntimeError::InvalidInput)?,
            );
        }
        let encryption_attempt_identifier =
            Zeroizing::new(unsafe { fixed_input(encryption_attempt_identifier_pointer) }?);
        let proof_attempt_nonce =
            Zeroizing::new(unsafe { fixed_input(proof_attempt_nonce_pointer) }?);
        let checkpoint_lineage_identifier =
            unsafe { fixed_input(checkpoint_lineage_identifier_pointer) }?;
        prepare_ballot_validity_generation(
            selected_suite_handle,
            action_randomness_handle,
            accepted_setup_authority_handle,
            producer_sequence,
            scores,
            encryption_attempt_identifier,
            proof_attempt_nonce,
            checkpoint_lineage_identifier,
            generation_mode,
        )
    })();
    match result {
        Ok(prepared) => {
            unsafe {
                ciphertext_readback_handle_output_pointer
                    .write(prepared.ciphertext_readback_handle);
                write_status(status_pointer, 0);
            }
            prepared.generation_family_adapter_handle
        }
        Err(error) => {
            unsafe { write_status(status_pointer, runtime_error_status(error)) };
            0
        }
    }
}

/// Creates the exact selected ballot encryption and a fresh common-proof
/// family adapter. The accepted setup, suite, application slot, statement,
/// relation plan, proof limits, and checkpoint schedule are all derived in
/// Rust from live capabilities.
///
/// # Safety
///
/// The score pointer must name exactly 20 little-endian `u64` values. Each
/// attempt pointer must name 32 readable bytes. The readback output pointer
/// must name one writable `u32`; a non-null status pointer must do the same.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_prepare_generation(
    selected_suite_handle: u32,
    action_randomness_handle: u32,
    accepted_setup_authority_handle: u32,
    producer_sequence: u64,
    scores_pointer: *const u8,
    scores_byte_length: usize,
    encryption_attempt_identifier_pointer: *const u8,
    proof_attempt_nonce_pointer: *const u8,
    checkpoint_lineage_identifier_pointer: *const u8,
    ciphertext_readback_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_from_ffi_inputs(
            selected_suite_handle,
            action_randomness_handle,
            accepted_setup_authority_handle,
            producer_sequence,
            scores_pointer,
            scores_byte_length,
            encryption_attempt_identifier_pointer,
            proof_attempt_nonce_pointer,
            checkpoint_lineage_identifier_pointer,
            ciphertext_readback_handle_output_pointer,
            status_pointer,
            BallotValidityGenerationMode::Fresh,
        )
    }
}

/// Recreates the exact ballot attempt and retains a resume adapter that can
/// only be activated by the generic runtime after it authenticates the
/// matching browser-owned checkpoint state.
///
/// # Safety
///
/// The score pointer must name exactly 20 little-endian `u64` values. Each
/// attempt pointer must name 32 readable bytes. The readback output pointer
/// must name one writable `u32`; a non-null status pointer must do the same.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_prepare_resumed_generation(
    selected_suite_handle: u32,
    action_randomness_handle: u32,
    accepted_setup_authority_handle: u32,
    producer_sequence: u64,
    scores_pointer: *const u8,
    scores_byte_length: usize,
    encryption_attempt_identifier_pointer: *const u8,
    proof_attempt_nonce_pointer: *const u8,
    checkpoint_lineage_identifier_pointer: *const u8,
    ciphertext_readback_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    unsafe {
        prepare_generation_from_ffi_inputs(
            selected_suite_handle,
            action_randomness_handle,
            accepted_setup_authority_handle,
            producer_sequence,
            scores_pointer,
            scores_byte_length,
            encryption_attempt_identifier_pointer,
            proof_attempt_nonce_pointer,
            checkpoint_lineage_identifier_pointer,
            ciphertext_readback_handle_output_pointer,
            status_pointer,
            BallotValidityGenerationMode::Resume,
        )
    }
}

/// Returns the exact canonical descriptor length for one generated ballot
/// ciphertext readback.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_ciphertext_descriptor_byte_length(
    ciphertext_readback_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let result = BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        u32::try_from(
            registry
                .entry(ciphertext_readback_handle)?
                .descriptor_bytes
                .len(),
        )
        .map_err(|_| BallotValidityRuntimeError::InvalidInput)
    });
    match result {
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

/// Copies the exact canonical descriptor for one generated ballot ciphertext.
///
/// # Safety
///
/// The output pointer must name its declared writable range. A non-null status
/// pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_copy_ciphertext_descriptor(
    ciphertext_readback_handle: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        let registry = registry.borrow();
        let descriptor_bytes = &registry.entry(ciphertext_readback_handle)?.descriptor_bytes;
        if output_pointer.is_null() || output_byte_length != descriptor_bytes.len() {
            return Err(BallotValidityRuntimeError::InvalidInput);
        }
        let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
        output.copy_from_slice(descriptor_bytes);
        Ok(())
    });
    match result {
        Ok(()) => {
            unsafe { write_status(status_pointer, 0) };
            0
        }
        Err(error) => {
            let status = runtime_error_status(error);
            unsafe { write_status(status_pointer, status) };
            status
        }
    }
}

/// Reads one sequential canonical ciphertext chunk. The caller supplies the
/// exact expected chunk index and output length derived from the descriptor;
/// a failed call does not advance the stream.
///
/// # Safety
///
/// The output pointer must name its declared writable range. A non-null status
/// pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_read_ciphertext_chunk(
    ciphertext_readback_handle: u32,
    chunk_index: u32,
    output_pointer: *mut u8,
    output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if output_pointer.is_null() {
            return Err(BallotValidityRuntimeError::InvalidInput);
        }
        let chunk_index =
            usize::try_from(chunk_index).map_err(|_| BallotValidityRuntimeError::InvalidInput)?;
        let expected_byte_length = BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
            let registry = registry.borrow();
            expected_ciphertext_chunk_byte_length(
                registry.entry(ciphertext_readback_handle)?,
                chunk_index,
            )
        })?;
        if output_byte_length != expected_byte_length {
            return Err(BallotValidityRuntimeError::InvalidInput);
        }
        let chunk = read_ciphertext_chunk(ciphertext_readback_handle, chunk_index)?;
        let output = unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) };
        output.copy_from_slice(&chunk);
        Ok(())
    })();
    match result {
        Ok(()) => {
            unsafe { write_status(status_pointer, 0) };
            0
        }
        Err(error) => {
            let status = runtime_error_status(error);
            unsafe { write_status(status_pointer, status) };
            status
        }
    }
}

/// Completes generated ciphertext readback after every authenticated chunk
/// has been copied exactly once. The exact descriptor remains live until the
/// generated proof is bound to its positively verified board package.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_validity_finish_ciphertext_readback(
    ciphertext_readback_handle: u32,
) -> u32 {
    BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .finish_readback(ciphertext_readback_handle)
            .map_or_else(runtime_error_status, |()| 0)
    })
}

/// Retains the exact direct-ballot envelope and returns its one-shot signing
/// handle. The ciphertext descriptor comes from the completed Rust readback;
/// the proof descriptor comes from the canonical output stream produced for
/// the same generation attempt. The roster is accepted only after canonical
/// decoding and equality with the statement-bound roster hash.
///
/// # Safety
///
/// Each nonempty input pointer must name its declared readable range. The
/// carrier-length output must name one writable `u32`; the signature-message
/// output must name exactly 64 writable bytes. A non-null status pointer must
/// name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_prepare_ballot_package_carrier(
    ciphertext_readback_handle: u32,
    proof_descriptor_pointer: *const u8,
    proof_descriptor_byte_length: usize,
    canonical_roster_pointer: *const u8,
    canonical_roster_byte_length: usize,
    canonical_carrier_byte_length_output_pointer: *mut u32,
    signature_message_output_pointer: *mut u8,
    signature_message_output_byte_length: usize,
    status_pointer: *mut u32,
) -> u32 {
    let result = (|| {
        if proof_descriptor_pointer.is_null()
            || canonical_roster_pointer.is_null()
            || canonical_carrier_byte_length_output_pointer.is_null()
            || signature_message_output_pointer.is_null()
            || signature_message_output_byte_length != Hash512::BYTE_LENGTH
        {
            return Err(BallotValidityRuntimeError::InvalidInput);
        }
        let proof_descriptor_bytes = unsafe {
            slice::from_raw_parts(proof_descriptor_pointer, proof_descriptor_byte_length)
        };
        let canonical_roster_bytes = unsafe {
            slice::from_raw_parts(canonical_roster_pointer, canonical_roster_byte_length)
        };
        let description = prepare_ballot_package_carrier(
            ciphertext_readback_handle,
            proof_descriptor_bytes,
            canonical_roster_bytes,
        )?;
        let canonical_carrier_byte_length =
            u32::try_from(description.canonical_carrier_byte_length())
                .map_err(|_| BallotValidityRuntimeError::InvalidInput)?;
        unsafe {
            canonical_carrier_byte_length_output_pointer.write(canonical_carrier_byte_length);
            slice::from_raw_parts_mut(
                signature_message_output_pointer,
                signature_message_output_byte_length,
            )
            .copy_from_slice(description.signature_message().as_bytes());
        }
        Ok(description.handle())
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

/// Completes one prepared direct-ballot carrier only after its participant
/// signature verifies against the statement-bound canonical roster.
///
/// # Safety
///
/// The signature pointer must name exactly one ML-DSA-65 signature. The output
/// pointer must name the exact writable length returned by preparation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_finish_ballot_package_carrier(
    prepared_carrier_handle: u32,
    signature_pointer: *const u8,
    signature_byte_length: usize,
    output_pointer: *mut u8,
    output_byte_length: usize,
) -> u32 {
    let result = (|| {
        if signature_pointer.is_null()
            || signature_byte_length != ML_DSA_65_SIGNATURE_BYTE_LENGTH
            || output_pointer.is_null()
        {
            return Err(BallotValidityRuntimeError::InvalidInput);
        }
        let expected_output_byte_length =
            prepared_signed_carrier_byte_length(prepared_carrier_handle)
                .map_err(BallotValidityRuntimeError::Refusal)?;
        if output_byte_length != expected_output_byte_length {
            return Err(BallotValidityRuntimeError::InvalidInput);
        }
        let signature = unsafe { fixed_input(signature_pointer) }?;
        let canonical_carrier = finish_prepared_signed_carrier(prepared_carrier_handle, signature)
            .map_err(BallotValidityRuntimeError::Refusal)?;
        if canonical_carrier.len() != output_byte_length {
            return Err(BallotValidityRuntimeError::InvalidInput);
        }
        unsafe { slice::from_raw_parts_mut(output_pointer, output_byte_length) }
            .copy_from_slice(&canonical_carrier);
        Ok(())
    })();
    result.map_or_else(runtime_error_status, |()| 0)
}

/// Cancels a prepared direct-ballot carrier after signing, board ingestion, or
/// another caller-owned step fails.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_validity_cancel_ballot_package_carrier(
    prepared_carrier_handle: u32,
) -> u32 {
    cancel_prepared_signed_carrier(prepared_carrier_handle).map_or_else(
        |reason| runtime_error_status(BallotValidityRuntimeError::Refusal(reason)),
        |()| 0,
    )
}

/// Consumes a generated proof and its completed ciphertext readback only
/// after one authenticated ballot package carries both exact descriptors and
/// every generation statement coordinate. This is the producer-side
/// post-output board binding; verification later derives fresh authority from
/// the same board object.
///
/// # Safety
///
/// The board capability pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_bind_generated_proof_to_board(
    generated_common_proof_handle: u32,
    ciphertext_readback_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    ballot_package_object_handle: u32,
) -> u32 {
    let board_verifier_session_capability = if board_verifier_session_capability_pointer.is_null() {
        &[]
    } else {
        unsafe {
            slice::from_raw_parts(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        }
    };
    bind_generated_ballot_validity_proof_to_board(
        generated_common_proof_handle,
        ciphertext_readback_handle,
        board_verifier_session_handle,
        board_verifier_session_capability,
        ballot_package_object_handle,
    )
    .map_or_else(runtime_error_status, |()| 0)
}

/// Permanently discards a ciphertext readback when its owning ballot attempt
/// is cancelled or will not be posted to the board.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_validity_discard_ciphertext_readback(
    ciphertext_readback_handle: u32,
) -> u32 {
    BALLOT_CIPHERTEXT_READBACK_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .discard(ciphertext_readback_handle)
            .map_or_else(runtime_error_status, |()| 0)
    })
}

/// Opens positive ballot verification from one authenticated board package.
/// The ciphertext descriptor is decoded only from that package and becomes
/// the sole authority for subsequent streamed ciphertext ingestion.
///
/// # Safety
///
/// The board capability pointer must name its declared readable range. A
/// non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_begin_verification(
    selected_suite_handle: u32,
    accepted_setup_authority_handle: u32,
    board_verifier_session_handle: u32,
    board_verifier_session_capability_pointer: *const u8,
    board_verifier_session_capability_byte_length: usize,
    ballot_package_object_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    let board_verifier_session_capability = if board_verifier_session_capability_pointer.is_null() {
        &[]
    } else {
        unsafe {
            slice::from_raw_parts(
                board_verifier_session_capability_pointer,
                board_verifier_session_capability_byte_length,
            )
        }
    };
    match begin_ballot_validity_verification(
        selected_suite_handle,
        accepted_setup_authority_handle,
        board_verifier_session_handle,
        board_verifier_session_capability,
        ballot_package_object_handle,
    ) {
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

/// Authenticates one sequential ballot-ciphertext chunk against the board
/// package descriptor before any coefficient becomes verifier material.
///
/// # Safety
///
/// The chunk pointer must name its declared readable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_absorb_ciphertext_chunk(
    preparation_handle: u32,
    chunk_index: u32,
    chunk_pointer: *const u8,
    chunk_byte_length: usize,
) -> u32 {
    if chunk_pointer.is_null() || chunk_byte_length == 0 {
        return refusal_status(RefusalReason::WrongTypeOrLength);
    }
    let chunk_bytes = unsafe { slice::from_raw_parts(chunk_pointer, chunk_byte_length) };
    absorb_ballot_ciphertext_chunk(preparation_handle, chunk_index as usize, chunk_bytes)
        .map_or_else(runtime_error_status, |()| 0)
}

/// Consumes a complete authenticated ciphertext stream and returns the
/// generic verifier-family adapter. The output handle owns the exact-family
/// terminal source that must consume the eventual positive common-proof
/// capability.
///
/// # Safety
///
/// The terminal-source output pointer must name one writable `u32`; a
/// non-null status pointer must do the same.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_finish_verification_preparation(
    preparation_handle: u32,
    terminal_source_handle_output_pointer: *mut u32,
    status_pointer: *mut u32,
) -> u32 {
    if terminal_source_handle_output_pointer.is_null() {
        let status = refusal_status(RefusalReason::WrongTypeOrLength);
        unsafe { write_status(status_pointer, status) };
        return 0;
    }
    match finish_ballot_validity_verification_preparation(preparation_handle) {
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

/// Cancels an incomplete ciphertext-verification preparation.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_validity_discard_verification_preparation(
    preparation_handle: u32,
) -> u32 {
    BALLOT_VALIDITY_VERIFICATION_PREPARATION_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(preparation_handle)
            .map_or_else(runtime_error_status, |_| 0)
    })
}

/// Consumes the positive common-proof verifier capability into a one-shot
/// verified ballot output. Every board, statement, descriptor, plan, query,
/// and variant binding is rechecked before the output handle is retained.
///
/// # Safety
///
/// A non-null status pointer must name one writable `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sealed_lattice_ballot_validity_finish_verification(
    verified_common_proof_handle: u32,
    terminal_source_handle: u32,
    status_pointer: *mut u32,
) -> u32 {
    match finish_ballot_validity_verification(verified_common_proof_handle, terminal_source_handle)
    {
        Ok(output_handle) => {
            unsafe { write_status(status_pointer, 0) };
            output_handle
        }
        Err(error) => {
            unsafe {
                write_status(
                    status_pointer,
                    super::runtime_ffi::runtime_error_status(error),
                )
            };
            0
        }
    }
}

/// Discards a terminal source after its generic verifier operation is
/// cancelled and can no longer produce a positive proof capability.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_validity_discard_verification_terminal_source(
    terminal_source_handle: u32,
) -> u32 {
    BALLOT_VALIDITY_VERIFICATION_TERMINAL_REGISTRY.with(|registry| {
        registry
            .borrow_mut()
            .take(terminal_source_handle)
            .map_or_else(runtime_error_status, |_| 0)
    })
}

/// Permanently drops a verified ballot output that will not enter evaluator
/// aggregation.
#[unsafe(no_mangle)]
pub extern "C" fn sealed_lattice_ballot_validity_discard_verified_output(
    output_handle: u32,
) -> u32 {
    consume_verified_ballot_validity_output(output_handle)
        .map_or_else(super::runtime_ffi::runtime_error_status, |_| 0)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::bgv::{direct_ballots::PAIR_CHARACTER_CIPHERTEXT_COUNT, parameters::DATA_PRIMES};

    use super::{
        derive_test_minted_ballot_ciphertext_descriptor,
        verified_ciphertext_catalog_from_authenticated,
    };

    const CIPHERTEXT_COMPONENT_COUNT: usize = 2;

    #[test]
    fn test_minted_ballot_descriptor_refuses_an_incomplete_catalog() {
        assert_eq!(
            derive_test_minted_ballot_ciphertext_descriptor(&[]),
            Err(crate::foundation::RefusalReason::WrongTypeOrLength),
        );
    }

    #[test]
    fn authenticated_ciphertext_conversion_preserves_all_selected_catalog_coordinates() {
        let data_modulus_count = DATA_PRIMES.len();
        let polynomials_per_ciphertext = CIPHERTEXT_COMPONENT_COUNT * data_modulus_count;
        let catalog_entry_count = PAIR_CHARACTER_CIPHERTEXT_COUNT * polynomials_per_ciphertext;
        assert_eq!(catalog_entry_count, 92);

        let authenticated_catalog = (0..catalog_entry_count)
            .map(|catalog_index| {
                let ciphertext_ordinal = catalog_index / polynomials_per_ciphertext;
                let component_ordinal =
                    (catalog_index % polynomials_per_ciphertext) / data_modulus_count;
                let data_modulus_index = catalog_index % data_modulus_count;
                (
                    u16::try_from(ciphertext_ordinal).expect("ciphertext ordinal fits u16"),
                    u16::try_from(component_ordinal).expect("component ordinal fits u16"),
                    u16::try_from(data_modulus_index).expect("data-modulus index fits u16"),
                    DATA_PRIMES[data_modulus_index],
                    Arc::<[u64]>::from(vec![
                        u64::try_from(catalog_index).expect("catalog index fits u64"),
                    ]),
                )
            })
            .collect::<Vec<_>>();

        let verified_catalog =
            verified_ciphertext_catalog_from_authenticated(authenticated_catalog);
        assert_eq!(verified_catalog.len(), 92);
        for (catalog_index, polynomial) in verified_catalog.iter().enumerate() {
            let expected_ciphertext_ordinal = catalog_index / polynomials_per_ciphertext;
            let expected_component_ordinal =
                (catalog_index % polynomials_per_ciphertext) / data_modulus_count;
            let expected_data_modulus_index = catalog_index % data_modulus_count;
            assert_eq!(
                (
                    usize::from(polynomial.ciphertext_ordinal()),
                    usize::from(polynomial.component_ordinal()),
                    usize::from(polynomial.data_modulus_index()),
                ),
                (
                    expected_ciphertext_ordinal,
                    expected_component_ordinal,
                    expected_data_modulus_index,
                ),
                "authenticated catalog coordinate changed at entry {catalog_index}",
            );
            assert_eq!(
                polynomial.modulus(),
                DATA_PRIMES[expected_data_modulus_index]
            );
            assert_eq!(
                polynomial.coefficients(),
                &[u64::try_from(catalog_index).expect("catalog index fits u64")]
            );
        }
    }

    #[test]
    fn authenticated_ciphertext_conversion_does_not_rederive_supplied_coordinates() {
        let authenticated_catalog = vec![
            (1, 1, 22, DATA_PRIMES[22], Arc::<[u64]>::from([41])),
            (0, 0, 0, DATA_PRIMES[0], Arc::<[u64]>::from([43])),
        ];

        let verified_catalog =
            verified_ciphertext_catalog_from_authenticated(authenticated_catalog);
        let coordinates = verified_catalog
            .iter()
            .map(|polynomial| {
                (
                    polynomial.ciphertext_ordinal(),
                    polynomial.component_ordinal(),
                    polynomial.data_modulus_index(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(coordinates, [(1, 1, 22), (0, 0, 0)]);
        assert_eq!(verified_catalog[0].coefficients(), &[41]);
        assert_eq!(verified_catalog[1].coefficients(), &[43]);
    }
}
