//! Test-only transport verification for the compact public-key proof.
//!
//! This fixture boundary owns the canonical byte pair, derives every
//! Fiat-Shamir message and component-authorized response query schedule from
//! those bytes, and verifies every salted response opening against the
//! selected contract. It does not provide a release verifier or claim that the
//! transported CFW or WHIR equations are valid.

use std::mem::size_of;

use super::compact_merkle_privacy::{
    CompactMerklePrivacyCertificate, CompactMerklePrivacyError,
    derive_and_validate_compact_response_query_schedule,
    derive_selected_compact_merkle_privacy_certificate,
};
use super::compact_proof_contract::{
    CompactProofContractError, CompactPublicKeyProofContract, CompactPublicKeyVerifierInputs,
};
use super::compact_proof_wire::{
    CompactProofWireError, CompactPublicInputBindings, DecodedCompactProofWire,
    DecodedCompactPublicInput, decode_compact_proof_wire, decode_compact_public_input,
};
use super::compact_response_merkle::CompactResponseQuerySchedule;
use super::compact_response_merkle::{
    CompactResponseMerkleError, verify_decoded_compact_response_opening,
};
use super::compact_transcript::{
    CompactTranscriptError, derive_compact_fiat_shamir_verifier_message,
};
use super::fixed_uniform_verifier_message::DecodedFixedUniformVerifierMessage;
use crate::foundation::Hash512;
use crate::hashing::{StreamingHash512, hash_framed_parts_512};

const COMPACT_TRANSPORT_PROOF_DIGEST_DOMAIN: &str =
    "sealed-lattice/bgv/compact-public-key-transport/proof/v1";
const COMPACT_TRANSPORT_PUBLIC_INPUT_DIGEST_DOMAIN: &str =
    "sealed-lattice/bgv/compact-public-key-transport/public-input/v1";
const COMPACT_TRANSPORT_PROGRESS_GENESIS_DOMAIN: &str =
    "sealed-lattice/bgv/compact-public-key-transport/progress-genesis/v1";
const COMPACT_TRANSPORT_VERIFIER_MESSAGE_DIGEST_DOMAIN: &str =
    "sealed-lattice/bgv/compact-public-key-transport/verifier-message/v1";
const COMPACT_TRANSPORT_PROGRESS_STEP_DOMAIN: &str =
    "sealed-lattice/bgv/compact-public-key-transport/progress-step/v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactPublicKeyTransportError {
    Contract(CompactProofContractError),
    Wire(CompactProofWireError),
    Transcript(CompactTranscriptError),
    Merkle(CompactResponseMerkleError),
    MerklePrivacy(CompactMerklePrivacyError),
    InvalidResponseRegistry,
    AllocationLimitExceeded,
    ArithmeticOverflow,
    CheckpointUnavailable,
    WrongCheckpoint,
    VerificationComplete,
}

impl From<CompactProofContractError> for CompactPublicKeyTransportError {
    fn from(error: CompactProofContractError) -> Self {
        Self::Contract(error)
    }
}

impl From<CompactProofWireError> for CompactPublicKeyTransportError {
    fn from(error: CompactProofWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<CompactTranscriptError> for CompactPublicKeyTransportError {
    fn from(error: CompactTranscriptError) -> Self {
        Self::Transcript(error)
    }
}

impl From<CompactResponseMerkleError> for CompactPublicKeyTransportError {
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::Merkle(error)
    }
}

impl From<CompactMerklePrivacyError> for CompactPublicKeyTransportError {
    fn from(error: CompactMerklePrivacyError) -> Self {
        Self::MerklePrivacy(error)
    }
}

/// Test-owned terminal for one compact byte pair whose transcript schedule and
/// salted Merkle openings have all been verified. Algebraic proof validity is
/// outside this type's guarantee.
pub(crate) struct VerifiedCompactPublicKeyTransport {
    contract: CompactPublicKeyProofContract,
    canonical_proof_bytes: Box<[u8]>,
    canonical_public_input_bytes: Box<[u8]>,
    decoded_proof: DecodedCompactProofWire,
    decoded_public_input: DecodedCompactPublicInput,
    verifier_messages: Box<[DecodedFixedUniformVerifierMessage]>,
}

/// Borrowed proof bytes inseparably paired with their decoded range owner.
pub(crate) struct VerifiedCompactProofTransportView<'transport> {
    canonical_bytes: &'transport [u8],
    decoded: &'transport DecodedCompactProofWire,
}

impl VerifiedCompactProofTransportView<'_> {
    pub(crate) const fn canonical_bytes(&self) -> &[u8] {
        self.canonical_bytes
    }

    pub(crate) const fn decoded(&self) -> &DecodedCompactProofWire {
        self.decoded
    }
}

/// Borrowed public-input bytes inseparably paired with their decoded range
/// owner.
pub(crate) struct VerifiedCompactPublicInputTransportView<'transport> {
    canonical_bytes: &'transport [u8],
    decoded: &'transport DecodedCompactPublicInput,
}

impl VerifiedCompactPublicInputTransportView<'_> {
    pub(crate) const fn canonical_bytes(&self) -> &[u8] {
        self.canonical_bytes
    }

    pub(crate) const fn decoded(&self) -> &DecodedCompactPublicInput {
        self.decoded
    }
}

impl VerifiedCompactPublicKeyTransport {
    pub(crate) fn verifier_inputs(&self) -> CompactPublicKeyVerifierInputs<'_> {
        self.contract.verifier_inputs()
    }

    pub(crate) fn proof_view(&self) -> VerifiedCompactProofTransportView<'_> {
        VerifiedCompactProofTransportView {
            canonical_bytes: &self.canonical_proof_bytes,
            decoded: &self.decoded_proof,
        }
    }

    pub(crate) fn public_input_view(&self) -> VerifiedCompactPublicInputTransportView<'_> {
        VerifiedCompactPublicInputTransportView {
            canonical_bytes: &self.canonical_public_input_bytes,
            decoded: &self.decoded_public_input,
        }
    }

    pub(crate) fn verifier_messages(&self) -> &[DecodedFixedUniformVerifierMessage] {
        &self.verifier_messages
    }
}

/// In-memory response-boundary token used to exercise exact replay and
/// substitution refusal in tests.
struct CompactPublicKeyTransportCheckpoint {
    contract_source_hash: Hash512,
    public_input_bindings: CompactPublicInputBindings,
    proof_digest: Hash512,
    public_input_digest: Hash512,
    completed_verifier_move_count: usize,
    verified_response_count: usize,
    verifier_messages: Vec<DecodedFixedUniformVerifierMessage>,
    progress_digest: Hash512,
}

pub(super) fn verify_selected_compact_public_key_transport_with_test_bindings(
    public_input_bindings: CompactPublicInputBindings,
    canonical_proof_bytes: Box<[u8]>,
    canonical_public_input_bytes: Box<[u8]>,
) -> Result<VerifiedCompactPublicKeyTransport, CompactPublicKeyTransportError> {
    let contract = CompactPublicKeyProofContract::decode_selected()?;
    let verifier_inputs = contract.verifier_inputs();
    let contract_source_hash = verifier_inputs.canonical_source_hash()?;
    let proof_digest = transport_byte_digest(
        COMPACT_TRANSPORT_PROOF_DIGEST_DOMAIN,
        &canonical_proof_bytes,
    );
    let public_input_digest = transport_byte_digest(
        COMPACT_TRANSPORT_PUBLIC_INPUT_DIGEST_DOMAIN,
        &canonical_public_input_bytes,
    );
    let merkle_privacy_certificate = derive_selected_compact_merkle_privacy_certificate()?;
    if merkle_privacy_certificate.contract_source_hash() != contract_source_hash
        || usize::try_from(merkle_privacy_certificate.response_commitment_count()).ok()
            != Some(verifier_inputs.response_merkle_geometries.len())
    {
        return Err(CompactPublicKeyTransportError::InvalidResponseRegistry);
    }
    let geometry = CompactPublicKeyTransportGeometry {
        contract_source_hash,
        public_input_wire_geometry: verifier_inputs.public_input_wire_geometry,
        proof_wire_geometry: verifier_inputs.proof_wire_geometry,
        response_merkle_geometries: verifier_inputs.response_merkle_geometries,
        completed_response_counts: verifier_inputs
            .checkpoint_schedule
            .completed_proof_response_counts(),
        expected_response_count: verifier_inputs.verifier_moves.len(),
    };
    let mut state = begin_compact_public_key_transport_bytes(
        geometry,
        public_input_bindings,
        &canonical_proof_bytes,
        &canonical_public_input_bytes,
        proof_digest,
        public_input_digest,
    )?;
    loop {
        match poll_compact_public_key_transport_bytes(
            &mut state,
            geometry,
            &canonical_proof_bytes,
            &canonical_public_input_bytes,
            Some(&merkle_privacy_certificate),
        )? {
            CompactPublicKeyTransportBytePoll::ResponseBoundary { .. } => {}
            CompactPublicKeyTransportBytePoll::Complete => {
                return Ok(VerifiedCompactPublicKeyTransport {
                    contract,
                    canonical_proof_bytes,
                    canonical_public_input_bytes,
                    decoded_proof: state.decoded_proof,
                    decoded_public_input: state.decoded_public_input,
                    verifier_messages: state.verifier_messages.into_boxed_slice(),
                });
            }
        }
    }
}

#[derive(Clone, Copy)]
struct CompactPublicKeyTransportGeometry<'geometry> {
    contract_source_hash: Hash512,
    public_input_wire_geometry: super::compact_proof_wire::CompactPublicInputWireGeometry,
    proof_wire_geometry: &'geometry super::compact_proof_wire::CompactProofWireGeometry,
    response_merkle_geometries:
        &'geometry [super::compact_response_merkle::CompactResponseMerkleGeometry],
    completed_response_counts: &'geometry [u32],
    expected_response_count: usize,
}

struct CompactPublicKeyTransportByteState {
    decoded_proof: DecodedCompactProofWire,
    decoded_public_input: DecodedCompactPublicInput,
    verifier_messages: Vec<DecodedFixedUniformVerifierMessage>,
    completed_verifier_move_count: usize,
    verified_response_count: usize,
    progress_digest: Hash512,
}

enum CompactPublicKeyTransportBytePoll {
    ResponseBoundary {
        completed_verifier_move_count: u32,
        verified_response_count: u32,
    },
    Complete,
}

#[derive(Clone, Copy)]
struct CompactOpeningVerificationBoundary<'boundary> {
    previous_verified_response_count: usize,
    canonical_proof_bytes: &'boundary [u8],
    move_index: usize,
    expected_verified_response_count: usize,
    merkle_privacy_certificate: Option<&'boundary CompactMerklePrivacyCertificate>,
}

#[derive(Clone, Copy)]
struct CompactTransportRestoreContext<'context> {
    geometry: CompactPublicKeyTransportGeometry<'context>,
    canonical_proof_bytes: &'context [u8],
    expected_public_input_bindings: CompactPublicInputBindings,
    expected_proof_digest: Hash512,
    expected_public_input_digest: Hash512,
    merkle_privacy_certificate: Option<&'context CompactMerklePrivacyCertificate>,
}

fn begin_compact_public_key_transport_bytes(
    geometry: CompactPublicKeyTransportGeometry<'_>,
    public_input_bindings: CompactPublicInputBindings,
    canonical_proof_bytes: &[u8],
    canonical_public_input_bytes: &[u8],
    proof_digest: Hash512,
    public_input_digest: Hash512,
) -> Result<CompactPublicKeyTransportByteState, CompactPublicKeyTransportError> {
    let decoded_proof =
        decode_compact_proof_wire(geometry.proof_wire_geometry, canonical_proof_bytes)?;
    let decoded_public_input = decode_compact_public_input(
        geometry.public_input_wire_geometry,
        public_input_bindings,
        canonical_public_input_bytes,
    )?;
    let response_count = geometry.proof_wire_geometry.responses().len();
    if response_count == 0
        || decoded_proof.responses().len() != response_count
        || geometry.response_merkle_geometries.len() != response_count
        || geometry.completed_response_counts.len() != response_count
        || geometry.expected_response_count != response_count
        || decoded_proof.canonical_byte_length() != canonical_proof_bytes.len()
        || decoded_public_input.canonical_byte_length() != canonical_public_input_bytes.len()
        || usize::try_from(*geometry.completed_response_counts.last().unwrap_or(&0)).ok()
            != Some(response_count)
    {
        return Err(CompactPublicKeyTransportError::InvalidResponseRegistry);
    }
    CompactResponseQuerySchedule::validate_registry(
        geometry.response_merkle_geometries,
        geometry.proof_wire_geometry.responses(),
    )?;
    let mut verifier_messages = Vec::new();
    verifier_messages
        .try_reserve_exact(response_count)
        .map_err(|_| CompactPublicKeyTransportError::AllocationLimitExceeded)?;
    Ok(CompactPublicKeyTransportByteState {
        decoded_proof,
        decoded_public_input,
        verifier_messages,
        completed_verifier_move_count: 0,
        verified_response_count: 0,
        progress_digest: compact_transport_progress_genesis(
            geometry.contract_source_hash,
            proof_digest,
            public_input_digest,
            response_count,
        )?,
    })
}

fn poll_compact_public_key_transport_bytes(
    state: &mut CompactPublicKeyTransportByteState,
    geometry: CompactPublicKeyTransportGeometry<'_>,
    canonical_proof_bytes: &[u8],
    canonical_public_input_bytes: &[u8],
    merkle_privacy_certificate: Option<&CompactMerklePrivacyCertificate>,
) -> Result<CompactPublicKeyTransportBytePoll, CompactPublicKeyTransportError> {
    let response_count = geometry.proof_wire_geometry.responses().len();
    let move_index = state.completed_verifier_move_count;
    if move_index >= response_count || state.verifier_messages.len() != move_index {
        return Err(CompactPublicKeyTransportError::VerificationComplete);
    }
    let move_ordinal = u32::try_from(move_index)
        .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    let verifier_message = derive_compact_fiat_shamir_verifier_message(
        geometry.proof_wire_geometry,
        &state.decoded_proof,
        canonical_proof_bytes,
        &state.decoded_public_input,
        canonical_public_input_bytes,
        move_ordinal,
    )?;
    state.verifier_messages.push(verifier_message);

    let expected_verified_response_count = usize::try_from(
        *geometry
            .completed_response_counts
            .get(move_index)
            .ok_or(CompactPublicKeyTransportError::InvalidResponseRegistry)?,
    )
    .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    let verify_result = verify_compact_openings_through_boundary(
        &state.decoded_proof,
        &state.verifier_messages,
        geometry,
        CompactOpeningVerificationBoundary {
            previous_verified_response_count: state.verified_response_count,
            canonical_proof_bytes,
            move_index,
            expected_verified_response_count,
            merkle_privacy_certificate,
        },
    );
    if let Err(error) = verify_result {
        state.verifier_messages.pop();
        return Err(error);
    }
    let completed_verifier_move_count = move_index
        .checked_add(1)
        .ok_or(CompactPublicKeyTransportError::ArithmeticOverflow)?;
    let progress_digest = compact_transport_progress_step(
        state.progress_digest,
        move_ordinal,
        expected_verified_response_count,
        state
            .verifier_messages
            .last()
            .ok_or(CompactPublicKeyTransportError::InvalidResponseRegistry)?,
    );
    let progress_digest = match progress_digest {
        Ok(digest) => digest,
        Err(error) => {
            state.verifier_messages.pop();
            return Err(error);
        }
    };
    state.completed_verifier_move_count = completed_verifier_move_count;
    state.verified_response_count = expected_verified_response_count;
    state.progress_digest = progress_digest;

    if completed_verifier_move_count == response_count {
        if expected_verified_response_count != response_count {
            return Err(CompactPublicKeyTransportError::InvalidResponseRegistry);
        }
        Ok(CompactPublicKeyTransportBytePoll::Complete)
    } else {
        Ok(CompactPublicKeyTransportBytePoll::ResponseBoundary {
            completed_verifier_move_count: u32::try_from(completed_verifier_move_count)
                .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?,
            verified_response_count: u32::try_from(expected_verified_response_count)
                .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?,
        })
    }
}

fn verify_compact_openings_through_boundary(
    decoded_proof: &DecodedCompactProofWire,
    verifier_message_prefix: &[DecodedFixedUniformVerifierMessage],
    geometry: CompactPublicKeyTransportGeometry<'_>,
    boundary: CompactOpeningVerificationBoundary<'_>,
) -> Result<(), CompactPublicKeyTransportError> {
    let CompactOpeningVerificationBoundary {
        previous_verified_response_count,
        canonical_proof_bytes,
        move_index,
        expected_verified_response_count,
        merkle_privacy_certificate,
    } = boundary;
    if expected_verified_response_count < previous_verified_response_count
        || expected_verified_response_count > geometry.expected_response_count
    {
        return Err(CompactPublicKeyTransportError::InvalidResponseRegistry);
    }
    let move_ordinal = u32::try_from(move_index)
        .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    for response_index in previous_verified_response_count..expected_verified_response_count {
        let decoded_response = &decoded_proof.responses()[response_index];
        let wire_geometry = &geometry.proof_wire_geometry.responses()[response_index];
        let merkle_geometry = &geometry.response_merkle_geometries[response_index];
        if usize::try_from(decoded_response.ordinal()).ok() != Some(response_index)
            || decoded_response.ordinal() != wire_geometry.ordinal()
            || decoded_response.ordinal() != merkle_geometry.response_ordinal()
            || merkle_geometry.last_query_verifier_move_ordinal() != move_ordinal
        {
            return Err(CompactPublicKeyTransportError::InvalidResponseRegistry);
        }
        let query_schedule = match merkle_privacy_certificate {
            Some(certificate) => derive_and_validate_compact_response_query_schedule(
                certificate,
                decoded_response.ordinal(),
                merkle_geometry,
                geometry.proof_wire_geometry.responses(),
                verifier_message_prefix,
            )?,
            #[cfg(test)]
            None => CompactResponseQuerySchedule::derive_at_last_query_boundary(
                merkle_geometry,
                geometry.proof_wire_geometry.responses(),
                verifier_message_prefix,
            )?,
            #[cfg(not(test))]
            None => return Err(CompactPublicKeyTransportError::InvalidResponseRegistry),
        };
        verify_decoded_compact_response_opening(
            merkle_geometry,
            wire_geometry,
            decoded_response,
            canonical_proof_bytes,
            &query_schedule,
        )?;
    }
    Ok(())
}

fn checkpoint_compact_public_key_transport_byte_state(
    state: &CompactPublicKeyTransportByteState,
    geometry: CompactPublicKeyTransportGeometry<'_>,
    public_input_bindings: CompactPublicInputBindings,
    proof_digest: Hash512,
    public_input_digest: Hash512,
) -> Result<CompactPublicKeyTransportCheckpoint, CompactPublicKeyTransportError> {
    if state.completed_verifier_move_count == 0
        || state.completed_verifier_move_count >= geometry.expected_response_count
        || state.verifier_messages.len() != state.completed_verifier_move_count
    {
        return Err(CompactPublicKeyTransportError::CheckpointUnavailable);
    }
    Ok(CompactPublicKeyTransportCheckpoint {
        contract_source_hash: geometry.contract_source_hash,
        public_input_bindings,
        proof_digest,
        public_input_digest,
        completed_verifier_move_count: state.completed_verifier_move_count,
        verified_response_count: state.verified_response_count,
        verifier_messages: state.verifier_messages.clone(),
        progress_digest: state.progress_digest,
    })
}

fn restore_compact_public_key_transport_byte_state(
    state: &mut CompactPublicKeyTransportByteState,
    context: CompactTransportRestoreContext<'_>,
    checkpoint: CompactPublicKeyTransportCheckpoint,
) -> Result<(), CompactPublicKeyTransportError> {
    let CompactTransportRestoreContext {
        geometry,
        canonical_proof_bytes,
        expected_public_input_bindings,
        expected_proof_digest,
        expected_public_input_digest,
        merkle_privacy_certificate,
    } = context;
    let completed_move_count = checkpoint.completed_verifier_move_count;
    if checkpoint.contract_source_hash != geometry.contract_source_hash
        || checkpoint.public_input_bindings != expected_public_input_bindings
        || checkpoint.proof_digest != expected_proof_digest
        || checkpoint.public_input_digest != expected_public_input_digest
        || completed_move_count == 0
        || completed_move_count >= geometry.expected_response_count
        || checkpoint.verifier_messages.len() != completed_move_count
    {
        return Err(CompactPublicKeyTransportError::WrongCheckpoint);
    }
    let expected_verified_response_count = usize::try_from(
        *geometry
            .completed_response_counts
            .get(completed_move_count - 1)
            .ok_or(CompactPublicKeyTransportError::WrongCheckpoint)?,
    )
    .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    if checkpoint.verified_response_count != expected_verified_response_count {
        return Err(CompactPublicKeyTransportError::WrongCheckpoint);
    }

    let mut recomputed_progress = state.progress_digest;
    let mut previous_verified_response_count = 0_usize;
    for move_index in 0..completed_move_count {
        let verified_response_count = usize::try_from(
            *geometry
                .completed_response_counts
                .get(move_index)
                .ok_or(CompactPublicKeyTransportError::WrongCheckpoint)?,
        )
        .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
        verify_compact_openings_through_boundary(
            &state.decoded_proof,
            &checkpoint.verifier_messages[..=move_index],
            geometry,
            CompactOpeningVerificationBoundary {
                previous_verified_response_count,
                canonical_proof_bytes,
                move_index,
                expected_verified_response_count: verified_response_count,
                merkle_privacy_certificate,
            },
        )?;
        recomputed_progress = compact_transport_progress_step(
            recomputed_progress,
            u32::try_from(move_index)
                .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?,
            verified_response_count,
            &checkpoint.verifier_messages[move_index],
        )?;
        previous_verified_response_count = verified_response_count;
    }
    if recomputed_progress != checkpoint.progress_digest {
        return Err(CompactPublicKeyTransportError::WrongCheckpoint);
    }
    state.verifier_messages = checkpoint.verifier_messages;
    state.completed_verifier_move_count = completed_move_count;
    state.verified_response_count = expected_verified_response_count;
    state.progress_digest = recomputed_progress;
    Ok(())
}

fn transport_byte_digest(domain: &str, bytes: &[u8]) -> Hash512 {
    let mut hasher = StreamingHash512::new(domain, 1);
    hasher.absorb_part(bytes);
    Hash512::from_bytes(hasher.finalize())
}

fn compact_transport_progress_genesis(
    contract_source_hash: Hash512,
    proof_digest: Hash512,
    public_input_digest: Hash512,
    response_count: usize,
) -> Result<Hash512, CompactPublicKeyTransportError> {
    let response_count = u32::try_from(response_count)
        .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    Ok(Hash512::from_bytes(hash_framed_parts_512(
        COMPACT_TRANSPORT_PROGRESS_GENESIS_DOMAIN,
        &[
            contract_source_hash.as_bytes(),
            proof_digest.as_bytes(),
            public_input_digest.as_bytes(),
            &response_count.to_le_bytes(),
        ],
    )))
}

fn compact_transport_progress_step(
    previous_progress_digest: Hash512,
    move_ordinal: u32,
    verified_response_count: usize,
    verifier_message: &DecodedFixedUniformVerifierMessage,
) -> Result<Hash512, CompactPublicKeyTransportError> {
    let message_digest = compact_verifier_message_digest(move_ordinal, verifier_message)?;
    let verified_response_count = u32::try_from(verified_response_count)
        .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    Ok(Hash512::from_bytes(hash_framed_parts_512(
        COMPACT_TRANSPORT_PROGRESS_STEP_DOMAIN,
        &[
            previous_progress_digest.as_bytes(),
            &move_ordinal.to_le_bytes(),
            &verified_response_count.to_le_bytes(),
            message_digest.as_bytes(),
        ],
    )))
}

fn compact_verifier_message_digest(
    move_ordinal: u32,
    message: &DecodedFixedUniformVerifierMessage,
) -> Result<Hash512, CompactPublicKeyTransportError> {
    let extension_count = u64::try_from(message.extension_elements().len())
        .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    let base_count = u64::try_from(message.base_field_elements().len())
        .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    let group_count = u64::try_from(message.distinct_query_groups().len())
        .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?;
    let encoded_byte_length = message
        .extension_elements()
        .len()
        .checked_mul(super::PROOF_CHALLENGE_EXTENSION_DEGREE)
        .and_then(|count| count.checked_add(message.base_field_elements().len()))
        .and_then(|count| {
            message
                .distinct_query_groups()
                .iter()
                .try_fold(count, |total, group| {
                    total.checked_add(1)?.checked_add(group.len())
                })
        })
        .and_then(|count| count.checked_add(3))
        .and_then(|count| count.checked_mul(size_of::<u64>()))
        .ok_or(CompactPublicKeyTransportError::ArithmeticOverflow)?;
    let mut hasher = StreamingHash512::new(COMPACT_TRANSPORT_VERIFIER_MESSAGE_DIGEST_DOMAIN, 2);
    hasher.absorb_part(&move_ordinal.to_le_bytes());
    hasher.begin_part(
        u64::try_from(encoded_byte_length)
            .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?,
    );
    hasher.absorb_raw(&extension_count.to_le_bytes());
    for extension in message.extension_elements() {
        for coordinate in extension.canonical_coordinates() {
            hasher.absorb_raw(&coordinate.to_le_bytes());
        }
    }
    hasher.absorb_raw(&base_count.to_le_bytes());
    for element in message.base_field_elements() {
        hasher.absorb_raw(&element.canonical().to_le_bytes());
    }
    hasher.absorb_raw(&group_count.to_le_bytes());
    for group in message.distinct_query_groups() {
        hasher.absorb_raw(
            &u64::try_from(group.len())
                .map_err(|_| CompactPublicKeyTransportError::ArithmeticOverflow)?
                .to_le_bytes(),
        );
        for ordinal in group {
            hasher.absorb_raw(&ordinal.to_le_bytes());
        }
    }
    Ok(Hash512::from_bytes(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
    use crate::bgv::proof_suite::compact_proof_wire::{
        COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireGeometry,
        CompactProofResponseWireInput, CompactProofWireGeometry, CompactProofWireInput,
        CompactPublicInputWireGeometry, PROOF_FIXED_HEADER_BYTE_LENGTH, encode_compact_proof_wire,
        encode_compact_public_input,
    };
    use crate::bgv::proof_suite::compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValue, CompactResponseLeafValueKind,
        CompactResponseMerkleGeometry, CompactResponseQuerySelection, compact_response_leaf_digest,
    };
    use crate::bgv::proof_suite::field::ProofBaseFieldElement;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::FixedUniformVerifierMessageGeometry;
    use crate::foundation::Hash512;

    struct SmallTransportFixture {
        contract_source_hash: Hash512,
        public_input_geometry: CompactPublicInputWireGeometry,
        proof_geometry: CompactProofWireGeometry,
        merkle_geometries: Vec<CompactResponseMerkleGeometry>,
        completed_response_counts: Vec<u32>,
        bindings: CompactPublicInputBindings,
        canonical_proof_bytes: Vec<u8>,
        canonical_public_input_bytes: Vec<u8>,
    }

    impl SmallTransportFixture {
        fn new() -> Self {
            let bindings = bindings(1);
            let public_input_geometry =
                CompactPublicInputWireGeometry::new(1, 1).expect("public-input geometry");
            let canonical_public_input_bytes =
                encode_compact_public_input(public_input_geometry, bindings, &[base(3)])
                    .expect("canonical public input");
            let verifier_message_geometry =
                FixedUniformVerifierMessageGeometry::new(0, 0, 1, Vec::new())
                    .expect("verifier-message geometry");
            let proof_geometry = CompactProofWireGeometry::new(
                (0..2)
                    .map(|ordinal| {
                        CompactProofResponseWireGeometry::new(
                            ordinal,
                            1,
                            0,
                            1,
                            0,
                            verifier_message_geometry.clone(),
                        )
                        .expect("response wire geometry")
                    })
                    .collect(),
            )
            .expect("proof wire geometry");
            let merkle_geometries = (0..2)
                .map(|ordinal| {
                    CompactResponseMerkleGeometry::new(
                        ordinal,
                        vec![CompactResponseComponentGeometry::new(
                            0,
                            1,
                            1,
                            CompactResponseQuerySelection::EveryLeaf,
                            CompactResponseLeafValueKind::BaseField,
                            1,
                        )],
                    )
                    .expect("response Merkle geometry")
                })
                .collect::<Vec<_>>();
            let response_inputs = merkle_geometries
                .iter()
                .enumerate()
                .map(|(response_index, merkle_geometry)| {
                    let opened_value = base(7 + response_index as u64);
                    let leaf_salt = [9 + u8::try_from(response_index)
                        .expect("small response index");
                        COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH];
                    let root = compact_response_leaf_digest(
                        merkle_geometry,
                        0,
                        CompactResponseLeafValue::BaseField(&[opened_value]),
                        &leaf_salt,
                    )
                    .expect("response root");
                    CompactProofResponseWireInput::new(
                        root,
                        [5 + u8::try_from(response_index).expect("small response index");
                            COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
                        vec![opened_value],
                        Vec::new(),
                        vec![leaf_salt],
                        Vec::new(),
                    )
                })
                .collect();
            let canonical_proof_bytes = encode_compact_proof_wire(
                &proof_geometry,
                &CompactProofWireInput::new(response_inputs),
            )
            .expect("canonical proof");
            Self {
                contract_source_hash: Hash512::from_bytes([0xA5; Hash512::BYTE_LENGTH]),
                public_input_geometry,
                proof_geometry,
                merkle_geometries,
                completed_response_counts: vec![1, 2],
                bindings,
                canonical_proof_bytes,
                canonical_public_input_bytes,
            }
        }

        fn verify(
            &self,
            expected_bindings: CompactPublicInputBindings,
            proof_bytes: &[u8],
            public_input_bytes: &[u8],
        ) -> Result<CompactPublicKeyTransportByteState, CompactPublicKeyTransportError> {
            self.verify_with_registry(
                expected_bindings,
                proof_bytes,
                public_input_bytes,
                &self.merkle_geometries,
                2,
            )
        }

        fn verify_with_registry(
            &self,
            expected_bindings: CompactPublicInputBindings,
            proof_bytes: &[u8],
            public_input_bytes: &[u8],
            merkle_geometries: &[CompactResponseMerkleGeometry],
            expected_response_count: usize,
        ) -> Result<CompactPublicKeyTransportByteState, CompactPublicKeyTransportError> {
            let geometry = CompactPublicKeyTransportGeometry {
                contract_source_hash: self.contract_source_hash,
                public_input_wire_geometry: self.public_input_geometry,
                proof_wire_geometry: &self.proof_geometry,
                response_merkle_geometries: merkle_geometries,
                completed_response_counts: &self.completed_response_counts,
                expected_response_count,
            };
            let proof_digest =
                transport_byte_digest(COMPACT_TRANSPORT_PROOF_DIGEST_DOMAIN, proof_bytes);
            let public_input_digest = transport_byte_digest(
                COMPACT_TRANSPORT_PUBLIC_INPUT_DIGEST_DOMAIN,
                public_input_bytes,
            );
            let mut state = begin_compact_public_key_transport_bytes(
                CompactPublicKeyTransportGeometry {
                    contract_source_hash: self.contract_source_hash,
                    public_input_wire_geometry: self.public_input_geometry,
                    proof_wire_geometry: &self.proof_geometry,
                    response_merkle_geometries: merkle_geometries,
                    completed_response_counts: &self.completed_response_counts,
                    expected_response_count,
                },
                expected_bindings,
                proof_bytes,
                public_input_bytes,
                proof_digest,
                public_input_digest,
            )?;
            loop {
                match poll_compact_public_key_transport_bytes(
                    &mut state,
                    geometry,
                    proof_bytes,
                    public_input_bytes,
                    None,
                )? {
                    CompactPublicKeyTransportBytePoll::ResponseBoundary { .. } => {}
                    CompactPublicKeyTransportBytePoll::Complete => return Ok(state),
                }
            }
        }

        fn begin_state(
            &self,
        ) -> Result<CompactPublicKeyTransportByteState, CompactPublicKeyTransportError> {
            let proof_digest = transport_byte_digest(
                COMPACT_TRANSPORT_PROOF_DIGEST_DOMAIN,
                &self.canonical_proof_bytes,
            );
            let public_input_digest = transport_byte_digest(
                COMPACT_TRANSPORT_PUBLIC_INPUT_DIGEST_DOMAIN,
                &self.canonical_public_input_bytes,
            );
            begin_compact_public_key_transport_bytes(
                self.geometry(),
                self.bindings,
                &self.canonical_proof_bytes,
                &self.canonical_public_input_bytes,
                proof_digest,
                public_input_digest,
            )
        }

        fn geometry(&self) -> CompactPublicKeyTransportGeometry<'_> {
            CompactPublicKeyTransportGeometry {
                contract_source_hash: self.contract_source_hash,
                public_input_wire_geometry: self.public_input_geometry,
                proof_wire_geometry: &self.proof_geometry,
                response_merkle_geometries: &self.merkle_geometries,
                completed_response_counts: &self.completed_response_counts,
                expected_response_count: self.merkle_geometries.len(),
            }
        }

        fn poll_state(
            &self,
            state: &mut CompactPublicKeyTransportByteState,
        ) -> Result<CompactPublicKeyTransportBytePoll, CompactPublicKeyTransportError> {
            poll_compact_public_key_transport_bytes(
                state,
                self.geometry(),
                &self.canonical_proof_bytes,
                &self.canonical_public_input_bytes,
                None,
            )
        }
    }

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("canonical base-field element")
    }

    fn bindings(tag: u8) -> CompactPublicInputBindings {
        CompactPublicInputBindings::new(
            Hash512::from_bytes([tag; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([tag.wrapping_add(1); Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([tag.wrapping_add(2); Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([tag.wrapping_add(3); Hash512::BYTE_LENGTH]),
        )
    }

    #[test]
    fn small_fixture_transport_verifies_without_retaining_query_schedules() {
        let fixture = SmallTransportFixture::new();
        let verified = fixture
            .verify(
                fixture.bindings,
                &fixture.canonical_proof_bytes,
                &fixture.canonical_public_input_bytes,
            )
            .expect("small transport verifies");
        assert_eq!(verified.decoded_proof.responses().len(), 2);
        assert_eq!(verified.verifier_messages.len(), 2);
    }

    #[test]
    fn polling_commits_one_response_boundary_and_checkpoint_restores_in_process() {
        let fixture = SmallTransportFixture::new();
        let mut uninterrupted = fixture.begin_state().expect("begin verifier");
        assert!(matches!(
            fixture.poll_state(&mut uninterrupted),
            Ok(CompactPublicKeyTransportBytePoll::ResponseBoundary {
                completed_verifier_move_count: 1,
                verified_response_count: 1,
            })
        ));
        let checkpoint = checkpoint_compact_public_key_transport_byte_state(
            &uninterrupted,
            fixture.geometry(),
            fixture.bindings,
            transport_byte_digest(
                COMPACT_TRANSPORT_PROOF_DIGEST_DOMAIN,
                &fixture.canonical_proof_bytes,
            ),
            transport_byte_digest(
                COMPACT_TRANSPORT_PUBLIC_INPUT_DIGEST_DOMAIN,
                &fixture.canonical_public_input_bytes,
            ),
        )
        .expect("in-memory boundary token");
        assert!(matches!(
            fixture.poll_state(&mut uninterrupted),
            Ok(CompactPublicKeyTransportBytePoll::Complete)
        ));

        let mut resumed = fixture.begin_state().expect("begin resumed verifier");
        restore_compact_public_key_transport_byte_state(
            &mut resumed,
            CompactTransportRestoreContext {
                geometry: fixture.geometry(),
                canonical_proof_bytes: &fixture.canonical_proof_bytes,
                expected_public_input_bindings: fixture.bindings,
                expected_proof_digest: transport_byte_digest(
                    COMPACT_TRANSPORT_PROOF_DIGEST_DOMAIN,
                    &fixture.canonical_proof_bytes,
                ),
                expected_public_input_digest: transport_byte_digest(
                    COMPACT_TRANSPORT_PUBLIC_INPUT_DIGEST_DOMAIN,
                    &fixture.canonical_public_input_bytes,
                ),
                merkle_privacy_certificate: None,
            },
            checkpoint,
        )
        .expect("restore in-process boundary token");
        assert_eq!(resumed.completed_verifier_move_count, 1);
        assert_eq!(resumed.verified_response_count, 1);
        assert!(matches!(
            fixture.poll_state(&mut resumed),
            Ok(CompactPublicKeyTransportBytePoll::Complete)
        ));
        assert_eq!(resumed.verifier_messages, uninterrupted.verifier_messages);
        assert_eq!(resumed.progress_digest, uninterrupted.progress_digest);
    }

    #[test]
    fn checkpoint_is_boundary_only_and_refuses_substitution_or_tampering() {
        let fixture = SmallTransportFixture::new();
        let mut state = fixture.begin_state().expect("begin verifier");
        assert!(matches!(
            checkpoint_compact_public_key_transport_byte_state(
                &state,
                fixture.geometry(),
                fixture.bindings,
                transport_byte_digest(
                    COMPACT_TRANSPORT_PROOF_DIGEST_DOMAIN,
                    &fixture.canonical_proof_bytes,
                ),
                transport_byte_digest(
                    COMPACT_TRANSPORT_PUBLIC_INPUT_DIGEST_DOMAIN,
                    &fixture.canonical_public_input_bytes,
                ),
            ),
            Err(CompactPublicKeyTransportError::CheckpointUnavailable)
        ));
        assert!(matches!(
            fixture.poll_state(&mut state),
            Ok(CompactPublicKeyTransportBytePoll::ResponseBoundary { .. })
        ));
        let checkpoint = checkpoint_compact_public_key_transport_byte_state(
            &state,
            fixture.geometry(),
            fixture.bindings,
            transport_byte_digest(
                COMPACT_TRANSPORT_PROOF_DIGEST_DOMAIN,
                &fixture.canonical_proof_bytes,
            ),
            transport_byte_digest(
                COMPACT_TRANSPORT_PUBLIC_INPUT_DIGEST_DOMAIN,
                &fixture.canonical_public_input_bytes,
            ),
        )
        .expect("boundary token");
        let CompactPublicKeyTransportCheckpoint {
            contract_source_hash,
            public_input_bindings,
            proof_digest,
            public_input_digest,
            completed_verifier_move_count,
            verified_response_count,
            verifier_messages,
            progress_digest,
        } = checkpoint;

        let mut substituted = fixture.begin_state().expect("begin substituted verifier");
        let wrong_proof_digest = Hash512::from_bytes([0xEE; Hash512::BYTE_LENGTH]);
        let substituted_checkpoint = CompactPublicKeyTransportCheckpoint {
            contract_source_hash,
            public_input_bindings,
            proof_digest: wrong_proof_digest,
            public_input_digest,
            completed_verifier_move_count,
            verified_response_count,
            verifier_messages: verifier_messages.clone(),
            progress_digest,
        };
        assert!(matches!(
            restore_compact_public_key_transport_byte_state(
                &mut substituted,
                CompactTransportRestoreContext {
                    geometry: fixture.geometry(),
                    canonical_proof_bytes: &fixture.canonical_proof_bytes,
                    expected_public_input_bindings: fixture.bindings,
                    expected_proof_digest: proof_digest,
                    expected_public_input_digest: public_input_digest,
                    merkle_privacy_certificate: None,
                },
                substituted_checkpoint,
            ),
            Err(CompactPublicKeyTransportError::WrongCheckpoint)
        ));

        let mut tampered = fixture.begin_state().expect("begin tampered verifier");
        let tampered_checkpoint = CompactPublicKeyTransportCheckpoint {
            contract_source_hash,
            public_input_bindings,
            proof_digest,
            public_input_digest,
            completed_verifier_move_count,
            verified_response_count,
            verifier_messages,
            progress_digest: Hash512::from_bytes([0xEF; Hash512::BYTE_LENGTH]),
        };
        assert!(matches!(
            restore_compact_public_key_transport_byte_state(
                &mut tampered,
                CompactTransportRestoreContext {
                    geometry: fixture.geometry(),
                    canonical_proof_bytes: &fixture.canonical_proof_bytes,
                    expected_public_input_bindings: fixture.bindings,
                    expected_proof_digest: proof_digest,
                    expected_public_input_digest: public_input_digest,
                    merkle_privacy_certificate: None,
                },
                tampered_checkpoint,
            ),
            Err(CompactPublicKeyTransportError::WrongCheckpoint)
        ));
    }

    #[test]
    fn malformed_truncated_and_trailing_transports_are_rejected() {
        let fixture = SmallTransportFixture::new();

        let mut malformed_proof = fixture.canonical_proof_bytes.clone();
        malformed_proof[0] ^= 1;
        let mut malformed_public_input = fixture.canonical_public_input_bytes.clone();
        malformed_public_input[0] ^= 1;
        assert!(matches!(
            fixture.verify(fixture.bindings, &malformed_proof, &malformed_public_input,),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::WrongProofMagic
            ))
        ));
        assert!(matches!(
            fixture.verify(
                fixture.bindings,
                &malformed_proof,
                &fixture.canonical_public_input_bytes,
            ),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::WrongProofMagic
            ))
        ));
        assert!(matches!(
            fixture.verify(
                fixture.bindings,
                &fixture.canonical_proof_bytes[..fixture.canonical_proof_bytes.len() - 1],
                &fixture.canonical_public_input_bytes,
            ),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::Truncated
            ))
        ));
        let mut trailing_proof = fixture.canonical_proof_bytes.clone();
        trailing_proof.push(0);
        assert!(matches!(
            fixture.verify(
                fixture.bindings,
                &trailing_proof,
                &fixture.canonical_public_input_bytes,
            ),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::GeometryBoundExceeded
            ))
        ));

        assert!(matches!(
            fixture.verify(
                fixture.bindings,
                &fixture.canonical_proof_bytes,
                &malformed_public_input,
            ),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::WrongPublicInputMagic
            ))
        ));
        assert!(matches!(
            fixture.verify(
                fixture.bindings,
                &fixture.canonical_proof_bytes,
                &fixture.canonical_public_input_bytes
                    [..fixture.canonical_public_input_bytes.len() - 1],
            ),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::Truncated
            ))
        ));
        let mut trailing_public_input = fixture.canonical_public_input_bytes.clone();
        trailing_public_input.push(0);
        assert!(matches!(
            fixture.verify(
                fixture.bindings,
                &fixture.canonical_proof_bytes,
                &trailing_public_input,
            ),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::TrailingBytes
            ))
        ));
    }

    #[test]
    fn public_input_binding_mismatch_is_a_wire_refusal() {
        let fixture = SmallTransportFixture::new();
        assert!(matches!(
            fixture.verify(
                bindings(20),
                &fixture.canonical_proof_bytes,
                &fixture.canonical_public_input_bytes,
            ),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::WrongPublicInputBinding
            ))
        ));
    }

    #[test]
    fn response_ordinal_and_registry_mutations_are_rejected() {
        let fixture = SmallTransportFixture::new();
        let mut wrong_ordinal = fixture.canonical_proof_bytes.clone();
        wrong_ordinal[PROOF_FIXED_HEADER_BYTE_LENGTH] = 1;
        assert!(matches!(
            fixture.verify(
                fixture.bindings,
                &wrong_ordinal,
                &fixture.canonical_public_input_bytes,
            ),
            Err(CompactPublicKeyTransportError::Wire(
                CompactProofWireError::WrongResponseOrdinal
            ))
        ));
        assert!(matches!(
            fixture.verify_with_registry(
                fixture.bindings,
                &fixture.canonical_proof_bytes,
                &fixture.canonical_public_input_bytes,
                &[],
                1,
            ),
            Err(CompactPublicKeyTransportError::InvalidResponseRegistry)
        ));
        assert!(matches!(
            fixture.verify_with_registry(
                fixture.bindings,
                &fixture.canonical_proof_bytes,
                &fixture.canonical_public_input_bytes,
                &fixture.merkle_geometries,
                1,
            ),
            Err(CompactPublicKeyTransportError::InvalidResponseRegistry)
        ));
        let wrong_merkle_registry = vec![
            fixture.merkle_geometries[1].clone(),
            fixture.merkle_geometries[0].clone(),
        ];
        assert!(matches!(
            fixture.verify_with_registry(
                fixture.bindings,
                &fixture.canonical_proof_bytes,
                &fixture.canonical_public_input_bytes,
                &wrong_merkle_registry,
                2,
            ),
            Err(CompactPublicKeyTransportError::Merkle(
                CompactResponseMerkleError::InvalidGeometry
            ))
        ));
    }

    #[test]
    fn root_value_and_leaf_salt_mutations_are_rejected() {
        let fixture = SmallTransportFixture::new();
        let response_root_offset = PROOF_FIXED_HEADER_BYTE_LENGTH + size_of::<u32>();
        let opened_value_offset = response_root_offset
            + Hash512::BYTE_LENGTH
            + COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH;
        let leaf_salt_offset = opened_value_offset + size_of::<u64>();
        for mutation_offset in [response_root_offset, opened_value_offset, leaf_salt_offset] {
            let mut mutated_proof = fixture.canonical_proof_bytes.clone();
            mutated_proof[mutation_offset] ^= 1;
            assert!(matches!(
                fixture.verify(
                    fixture.bindings,
                    &mutated_proof,
                    &fixture.canonical_public_input_bytes,
                ),
                Err(CompactPublicKeyTransportError::Merkle(
                    CompactResponseMerkleError::RootMismatch
                ))
            ));
        }
    }
}
