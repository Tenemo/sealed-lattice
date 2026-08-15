//! Canonical Fiat-Shamir transcript for the compact ring-vector construction.
//!
//! CDHZ Construction 11.7 derives round `i` from the explicit instance, every
//! vector-commitment pair through `i`, and every independent round salt
//! through `i`. The compact construction fixes commitment-oracle identifier
//! `i + 1`, so the identifier is verifier-derived and is not transported.
//! Streaming prefix construction and verifier-message derivation are ordinary
//! release code. Prover checkpoint cursors remain test-only until the compact
//! generation state consumes them.
//!
//! The resulting 512-bit prefix digest feeds the fixed-width verifier-message
//! seed and predecessor-linked block schedule. That concrete multi-call
//! SHAKE256 graph still needs its separate emitted-byte QROM correspondence;
//! this module does not equate the graph with one ideal variable-output call.

use std::mem::size_of;

#[cfg(test)]
use super::compact_proof_wire::decode_compact_proof_wire_prefix;
use super::compact_proof_wire::{
    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, COMPACT_PACKING_FACTOR, CompactProofWireError,
    CompactProofWireGeometry, DecodedCompactProofWire, DecodedCompactPublicInput,
};
use super::fixed_uniform_verifier_message::{
    DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageError,
    derive_fixed_uniform_verifier_message,
};
use crate::foundation::{
    CanonicalItem, Hash512, StreamingFoundationHashError, StreamingFoundationTupleHash512,
};

pub(crate) const COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN: &str =
    "sealed-lattice/proof/compact-fiat-shamir-prefix/v1";
pub(crate) const COMPACT_FIAT_SHAMIR_PREFIX_VERSION: u16 = 1;
const COMMITMENT_PREFIX_ENTRY_BYTE_LENGTH: usize =
    size_of::<u32>() + Hash512::BYTE_LENGTH + COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH;
#[cfg(test)]
const COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_MAGIC: [u8; 8] = *b"SLCTCP01";
#[cfg(test)]
const COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_VERSION: u16 = 1;
#[cfg(test)]
const COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_HEADER_BYTE_LENGTH: usize = 8
    + 2 * size_of::<u16>()
    + size_of::<u32>()
    + 2 * size_of::<u16>()
    + 2 * size_of::<u32>()
    + size_of::<u64>()
    + 2 * Hash512::BYTE_LENGTH;
#[cfg(test)]
const COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_ENTRY_BYTE_LENGTH: usize =
    size_of::<u32>() + Hash512::BYTE_LENGTH + COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH;
#[cfg(test)]
pub(crate) const MAXIMUM_COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH: usize = 16 * 1_024;
const COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_DIGEST_DOMAIN: &str =
    "sealed-lattice/proof/compact-transcript-checkpoint-cursor/v1";
const COMPACT_TRANSCRIPT_CHECKPOINT_PUBLIC_INPUT_DIGEST_DOMAIN: &str =
    "sealed-lattice/proof/compact-transcript-checkpoint-public-input/v1";
const COMPACT_PROOF_WIRE_GEOMETRY_DIGEST_DOMAIN: &str =
    "sealed-lattice/proof/compact-proof-wire-geometry/v1";
#[cfg(test)]
const COMPACT_PROOF_WIRE_GEOMETRY_DIGEST_VERSION: u16 = 1;

pub(crate) const fn compact_transcript_binding_domains() -> [&'static str; 4] {
    [
        COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN,
        COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_DIGEST_DOMAIN,
        COMPACT_TRANSCRIPT_CHECKPOINT_PUBLIC_INPUT_DIGEST_DOMAIN,
        COMPACT_PROOF_WIRE_GEOMETRY_DIGEST_DOMAIN,
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactTranscriptError {
    InvalidGeometry,
    LengthOverflow,
    #[cfg(test)]
    AllocationLimitExceeded,
    #[cfg(test)]
    WrongProverPhase,
    #[cfg(test)]
    WrongCheckpointCursor,
    #[cfg(test)]
    CheckpointCursorDigestMismatch,
    Wire(CompactProofWireError),
    FoundationHash(StreamingFoundationHashError),
    VerifierMessage(FixedUniformVerifierMessageError),
}

impl From<CompactProofWireError> for CompactTranscriptError {
    fn from(error: CompactProofWireError) -> Self {
        Self::Wire(error)
    }
}

impl From<StreamingFoundationHashError> for CompactTranscriptError {
    fn from(error: StreamingFoundationHashError) -> Self {
        Self::FoundationHash(error)
    }
}

impl From<FixedUniformVerifierMessageError> for CompactTranscriptError {
    fn from(error: FixedUniformVerifierMessageError) -> Self {
        Self::VerifierMessage(error)
    }
}

/// Returns the fixed, one-based CDHZ vector-commitment oracle identifier.
pub(crate) fn compact_vector_commitment_oracle_identifier(
    response_ordinal: u32,
) -> Result<u32, CompactTranscriptError> {
    response_ordinal
        .checked_add(1)
        .ok_or(CompactTranscriptError::LengthOverflow)
}

/// Exact raw payload absorbed by the round-prefix hash.
pub(crate) fn compact_fiat_shamir_prefix_payload_byte_length(
    canonical_public_input_byte_length: usize,
    prefix_response_count: usize,
) -> Result<usize, CompactTranscriptError> {
    if canonical_public_input_byte_length == 0 || prefix_response_count == 0 {
        return Err(CompactTranscriptError::InvalidGeometry);
    }
    size_of::<u64>()
        .checked_add(canonical_public_input_byte_length)
        .and_then(|byte_length| {
            prefix_response_count
                .checked_mul(COMMITMENT_PREFIX_ENTRY_BYTE_LENGTH)
                .and_then(|prefix_byte_length| byte_length.checked_add(prefix_byte_length))
        })
        .ok_or(CompactTranscriptError::LengthOverflow)
}

pub(crate) fn compact_fiat_shamir_round_prefix_digest(
    geometry: &CompactProofWireGeometry,
    decoded_proof: &DecodedCompactProofWire,
    canonical_proof_bytes: &[u8],
    decoded_public_input: &DecodedCompactPublicInput,
    canonical_public_input_bytes: &[u8],
    logical_verifier_move_ordinal: u32,
) -> Result<Hash512, CompactTranscriptError> {
    if decoded_proof.canonical_byte_length() != canonical_proof_bytes.len()
        || decoded_public_input.canonical_byte_length() != canonical_public_input_bytes.len()
        || decoded_proof.responses().len() != geometry.responses().len()
    {
        return Err(CompactTranscriptError::InvalidGeometry);
    }
    let current_response_index = usize::try_from(logical_verifier_move_ordinal)
        .map_err(|_| CompactTranscriptError::LengthOverflow)?;
    let prefix_response_count = current_response_index
        .checked_add(1)
        .ok_or(CompactTranscriptError::LengthOverflow)?;
    if prefix_response_count > decoded_proof.responses().len()
        || geometry
            .responses()
            .get(current_response_index)
            .is_none_or(|response| response.ordinal() != logical_verifier_move_ordinal)
    {
        return Err(CompactTranscriptError::InvalidGeometry);
    }

    compact_fiat_shamir_prefix_digest_from_entries(
        geometry,
        canonical_public_input_bytes,
        logical_verifier_move_ordinal,
        decoded_proof.responses()[..prefix_response_count]
            .iter()
            .map(|response| {
                Ok(CompactTranscriptCommitmentEntry {
                    root: response.root(),
                    fiat_shamir_round_salt: response
                        .fiat_shamir_round_salt(canonical_proof_bytes)?,
                })
            }),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CompactTranscriptCommitmentEntry {
    root: [u8; Hash512::BYTE_LENGTH],
    fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
}

fn compact_fiat_shamir_prefix_digest_from_entries(
    geometry: &CompactProofWireGeometry,
    canonical_public_input_bytes: &[u8],
    logical_verifier_move_ordinal: u32,
    entries: impl IntoIterator<Item = Result<CompactTranscriptCommitmentEntry, CompactTranscriptError>>,
) -> Result<Hash512, CompactTranscriptError> {
    let current_response_index = usize::try_from(logical_verifier_move_ordinal)
        .map_err(|_| CompactTranscriptError::LengthOverflow)?;
    let prefix_response_count = current_response_index
        .checked_add(1)
        .ok_or(CompactTranscriptError::LengthOverflow)?;
    if prefix_response_count > geometry.responses().len()
        || geometry
            .responses()
            .get(current_response_index)
            .is_none_or(|response| response.ordinal() != logical_verifier_move_ordinal)
    {
        return Err(CompactTranscriptError::InvalidGeometry);
    }
    let payload_byte_length = compact_fiat_shamir_prefix_payload_byte_length(
        canonical_public_input_bytes.len(),
        prefix_response_count,
    )?;
    let mut hasher = StreamingFoundationTupleHash512::new_variable_bytes(
        COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN,
        &[
            CanonicalItem::unsigned16(COMPACT_FIAT_SHAMIR_PREFIX_VERSION),
            CanonicalItem::unsigned16(COMPACT_PACKING_FACTOR),
            CanonicalItem::unsigned32(logical_verifier_move_ordinal),
            CanonicalItem::unsigned32(
                u32::try_from(prefix_response_count)
                    .map_err(|_| CompactTranscriptError::LengthOverflow)?,
            ),
        ],
        payload_byte_length,
    )?;
    hasher.absorb(
        &u64::try_from(canonical_public_input_bytes.len())
            .map_err(|_| CompactTranscriptError::LengthOverflow)?
            .to_le_bytes(),
    )?;
    hasher.absorb(canonical_public_input_bytes)?;
    let mut absorbed_entry_count = 0_usize;
    for (response_index, entry) in entries.into_iter().enumerate() {
        if response_index >= prefix_response_count {
            return Err(CompactTranscriptError::InvalidGeometry);
        }
        let entry = entry?;
        let response_ordinal =
            u32::try_from(response_index).map_err(|_| CompactTranscriptError::LengthOverflow)?;
        hasher.absorb(
            &compact_vector_commitment_oracle_identifier(response_ordinal)?.to_le_bytes(),
        )?;
        hasher.absorb(&entry.root)?;
        hasher.absorb(&entry.fiat_shamir_round_salt)?;
        absorbed_entry_count = absorbed_entry_count
            .checked_add(1)
            .ok_or(CompactTranscriptError::LengthOverflow)?;
    }
    if absorbed_entry_count != prefix_response_count {
        return Err(CompactTranscriptError::InvalidGeometry);
    }
    hasher.finalize().map_err(Into::into)
}

/// Prover-side owner of the exact commitment prefix used by Fiat-Shamir.
///
/// A response root and its independent public round salt must be recorded
/// together. The corresponding verifier message must then be derived exactly
/// once before the next response can be recorded. Response contents and proof
/// openings remain owned by the proof assembler; this state retains only the
/// bytes that the challenge prefix actually absorbs.
#[cfg(test)]
pub(crate) struct CompactProverTranscript<'input> {
    geometry: &'input CompactProofWireGeometry,
    canonical_public_input_bytes: &'input [u8],
    commitment_entries: Vec<CompactTranscriptCommitmentEntry>,
    verifier_message_pending: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg(test)]
pub(crate) struct CompactTranscriptCheckpointCursor {
    canonical_bytes: Vec<u8>,
    digest: [u8; Hash512::BYTE_LENGTH],
}

#[cfg(test)]
impl CompactTranscriptCheckpointCursor {
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) const fn digest(&self) -> [u8; Hash512::BYTE_LENGTH] {
        self.digest
    }

    pub(crate) fn into_canonical_bytes(self) -> Vec<u8> {
        self.canonical_bytes
    }
}

#[cfg(test)]
fn compact_proof_wire_geometry_digest(
    geometry: &CompactProofWireGeometry,
) -> Result<Hash512, CompactTranscriptError> {
    let response_fixed_payload_byte_length = size_of::<u32>()
        .checked_add(
            10_usize
                .checked_mul(size_of::<u64>())
                .ok_or(CompactTranscriptError::LengthOverflow)?,
        )
        .and_then(|byte_length| byte_length.checked_add(size_of::<u32>()))
        .ok_or(CompactTranscriptError::LengthOverflow)?;
    let payload_byte_length =
        geometry
            .responses()
            .iter()
            .try_fold(0_usize, |byte_length, response| {
                response
                    .verifier_message_geometry()
                    .distinct_query_groups()
                    .len()
                    .checked_mul(2 * size_of::<u64>())
                    .and_then(|query_byte_length| {
                        response_fixed_payload_byte_length.checked_add(query_byte_length)
                    })
                    .and_then(|response_byte_length| byte_length.checked_add(response_byte_length))
                    .ok_or(CompactTranscriptError::LengthOverflow)
            })?;
    let mut hasher = StreamingFoundationTupleHash512::new_variable_bytes(
        COMPACT_PROOF_WIRE_GEOMETRY_DIGEST_DOMAIN,
        &[
            CanonicalItem::unsigned16(COMPACT_PROOF_WIRE_GEOMETRY_DIGEST_VERSION),
            CanonicalItem::unsigned16(COMPACT_PACKING_FACTOR),
            CanonicalItem::unsigned32(
                u32::try_from(geometry.responses().len())
                    .map_err(|_| CompactTranscriptError::LengthOverflow)?,
            ),
        ],
        payload_byte_length,
    )?;
    for response in geometry.responses() {
        hasher.absorb(&response.ordinal().to_le_bytes())?;
        for count in [
            response.minimum_queried_base_field_element_count(),
            response.maximum_queried_base_field_element_count(),
            response.minimum_queried_extension_field_element_count(),
            response.maximum_queried_extension_field_element_count(),
            response.minimum_queried_leaf_count(),
            response.maximum_queried_leaf_count(),
            response.maximum_frontier_node_count(),
        ] {
            hasher.absorb(&count.to_le_bytes())?;
        }
        let verifier_message_geometry = response.verifier_message_geometry();
        for count in [
            verifier_message_geometry.extension_output_count(),
            verifier_message_geometry.excluded_extension_prefix_cardinality(),
            verifier_message_geometry.base_field_output_count(),
        ] {
            hasher.absorb(&count.to_le_bytes())?;
        }
        hasher.absorb(
            &u32::try_from(verifier_message_geometry.distinct_query_groups().len())
                .map_err(|_| CompactTranscriptError::LengthOverflow)?
                .to_le_bytes(),
        )?;
        for query_group in verifier_message_geometry.distinct_query_groups() {
            hasher.absorb(&query_group.domain_cardinality().to_le_bytes())?;
            hasher.absorb(&query_group.query_count().to_le_bytes())?;
        }
    }
    hasher.finalize().map_err(Into::into)
}

#[cfg(test)]
fn compact_transcript_checkpoint_public_input_digest(
    canonical_public_input_bytes: &[u8],
) -> [u8; Hash512::BYTE_LENGTH] {
    crate::hashing::hash_framed_parts_512(
        COMPACT_TRANSCRIPT_CHECKPOINT_PUBLIC_INPUT_DIGEST_DOMAIN,
        &[canonical_public_input_bytes],
    )
}

#[cfg(test)]
fn compact_transcript_checkpoint_cursor_digest(
    canonical_cursor_bytes: &[u8],
) -> [u8; Hash512::BYTE_LENGTH] {
    crate::hashing::hash_framed_parts_512(
        COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_DIGEST_DOMAIN,
        &[canonical_cursor_bytes],
    )
}

#[cfg(test)]
impl<'input> CompactProverTranscript<'input> {
    pub(crate) fn new(
        geometry: &'input CompactProofWireGeometry,
        decoded_public_input: &DecodedCompactPublicInput,
        canonical_public_input_bytes: &'input [u8],
    ) -> Result<Self, CompactTranscriptError> {
        if geometry.responses().is_empty()
            || decoded_public_input.canonical_byte_length() != canonical_public_input_bytes.len()
        {
            return Err(CompactTranscriptError::InvalidGeometry);
        }
        let mut commitment_entries = Vec::new();
        commitment_entries
            .try_reserve_exact(geometry.responses().len())
            .map_err(|_| CompactTranscriptError::AllocationLimitExceeded)?;
        if commitment_entries.capacity() != geometry.responses().len() {
            return Err(CompactTranscriptError::AllocationLimitExceeded);
        }
        Ok(Self {
            geometry,
            canonical_public_input_bytes,
            commitment_entries,
            verifier_message_pending: false,
        })
    }

    pub(crate) const fn completed_response_count(&self) -> usize {
        self.commitment_entries.len()
    }

    pub(crate) fn total_response_count(&self) -> usize {
        self.geometry.responses().len()
    }

    /// Encodes the complete canonical commitment prefix at a deterministic
    /// post-verifier-move boundary. No opaque SHAKE state is serialized.
    pub(crate) fn checkpoint_cursor(
        &self,
    ) -> Result<CompactTranscriptCheckpointCursor, CompactTranscriptError> {
        if self.verifier_message_pending || self.commitment_entries.is_empty() {
            return Err(CompactTranscriptError::WrongProverPhase);
        }
        let total_byte_length = COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_HEADER_BYTE_LENGTH
            .checked_add(
                self.commitment_entries
                    .len()
                    .checked_mul(COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_ENTRY_BYTE_LENGTH)
                    .ok_or(CompactTranscriptError::LengthOverflow)?,
            )
            .filter(|byte_length| {
                *byte_length <= MAXIMUM_COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH
            })
            .ok_or(CompactTranscriptError::AllocationLimitExceeded)?;
        let mut canonical_bytes = Vec::new();
        canonical_bytes
            .try_reserve_exact(total_byte_length)
            .map_err(|_| CompactTranscriptError::AllocationLimitExceeded)?;
        if canonical_bytes.capacity() != total_byte_length {
            return Err(CompactTranscriptError::AllocationLimitExceeded);
        }
        canonical_bytes.extend_from_slice(&COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_MAGIC);
        canonical_bytes
            .extend_from_slice(&COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_VERSION.to_le_bytes());
        canonical_bytes.extend_from_slice(&0_u16.to_le_bytes());
        canonical_bytes.extend_from_slice(
            &u32::try_from(total_byte_length)
                .map_err(|_| CompactTranscriptError::LengthOverflow)?
                .to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(&COMPACT_PACKING_FACTOR.to_le_bytes());
        canonical_bytes.extend_from_slice(&0_u16.to_le_bytes());
        canonical_bytes.extend_from_slice(
            &u32::try_from(self.geometry.responses().len())
                .map_err(|_| CompactTranscriptError::LengthOverflow)?
                .to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(
            &u32::try_from(self.commitment_entries.len())
                .map_err(|_| CompactTranscriptError::LengthOverflow)?
                .to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(
            &u64::try_from(self.canonical_public_input_bytes.len())
                .map_err(|_| CompactTranscriptError::LengthOverflow)?
                .to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(&compact_transcript_checkpoint_public_input_digest(
            self.canonical_public_input_bytes,
        ));
        canonical_bytes
            .extend_from_slice(compact_proof_wire_geometry_digest(self.geometry)?.as_bytes());
        for (response_index, entry) in self.commitment_entries.iter().enumerate() {
            canonical_bytes.extend_from_slice(
                &u32::try_from(response_index)
                    .map_err(|_| CompactTranscriptError::LengthOverflow)?
                    .to_le_bytes(),
            );
            canonical_bytes.extend_from_slice(&entry.root);
            canonical_bytes.extend_from_slice(&entry.fiat_shamir_round_salt);
        }
        if canonical_bytes.len() != total_byte_length {
            return Err(CompactTranscriptError::WrongCheckpointCursor);
        }
        let digest = compact_transcript_checkpoint_cursor_digest(&canonical_bytes);
        Ok(CompactTranscriptCheckpointCursor {
            canonical_bytes,
            digest,
        })
    }

    /// Recomputes every completed verifier message from canonical bytes and
    /// returns the live transcript at the next prover-move boundary.
    pub(crate) fn restore_from_checkpoint_cursor(
        geometry: &'input CompactProofWireGeometry,
        decoded_public_input: &DecodedCompactPublicInput,
        canonical_public_input_bytes: &'input [u8],
        canonical_cursor_bytes: &[u8],
        expected_cursor_digest: [u8; Hash512::BYTE_LENGTH],
    ) -> Result<Self, CompactTranscriptError> {
        if canonical_cursor_bytes.len() > MAXIMUM_COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH
            || compact_transcript_checkpoint_cursor_digest(canonical_cursor_bytes)
                != expected_cursor_digest
        {
            return Err(CompactTranscriptError::CheckpointCursorDigestMismatch);
        }
        let mut reader = CompactTranscriptCheckpointCursorReader::new(canonical_cursor_bytes);
        if reader.read_array::<8>()? != COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_MAGIC
            || reader.read_u16()? != COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_VERSION
            || reader.read_u16()? != 0
        {
            return Err(CompactTranscriptError::WrongCheckpointCursor);
        }
        let declared_total_byte_length = usize::try_from(reader.read_u32()?)
            .map_err(|_| CompactTranscriptError::LengthOverflow)?;
        let packing_factor = reader.read_u16()?;
        let reserved = reader.read_u16()?;
        let total_response_count = usize::try_from(reader.read_u32()?)
            .map_err(|_| CompactTranscriptError::LengthOverflow)?;
        let completed_response_count = usize::try_from(reader.read_u32()?)
            .map_err(|_| CompactTranscriptError::LengthOverflow)?;
        let canonical_public_input_byte_length = usize::try_from(reader.read_u64()?)
            .map_err(|_| CompactTranscriptError::LengthOverflow)?;
        let public_input_digest = reader.read_array::<{ Hash512::BYTE_LENGTH }>()?;
        let geometry_digest = reader.read_array::<{ Hash512::BYTE_LENGTH }>()?;
        let expected_total_byte_length = COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_HEADER_BYTE_LENGTH
            .checked_add(
                completed_response_count
                    .checked_mul(COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_ENTRY_BYTE_LENGTH)
                    .ok_or(CompactTranscriptError::LengthOverflow)?,
            )
            .ok_or(CompactTranscriptError::LengthOverflow)?;
        if declared_total_byte_length != canonical_cursor_bytes.len()
            || expected_total_byte_length != canonical_cursor_bytes.len()
            || reserved != 0
            || packing_factor != COMPACT_PACKING_FACTOR
            || total_response_count != geometry.responses().len()
            || completed_response_count == 0
            || completed_response_count > total_response_count
            || canonical_public_input_byte_length != canonical_public_input_bytes.len()
            || public_input_digest
                != compact_transcript_checkpoint_public_input_digest(canonical_public_input_bytes)
            || geometry_digest != compact_proof_wire_geometry_digest(geometry)?.into_bytes()
        {
            return Err(CompactTranscriptError::WrongCheckpointCursor);
        }

        let mut transcript =
            Self::new(geometry, decoded_public_input, canonical_public_input_bytes)?;
        for response_index in 0..completed_response_count {
            let response_ordinal = reader.read_u32()?;
            if usize::try_from(response_ordinal).ok() != Some(response_index) {
                return Err(CompactTranscriptError::WrongCheckpointCursor);
            }
            let root = reader.read_array::<{ Hash512::BYTE_LENGTH }>()?;
            let fiat_shamir_round_salt =
                reader.read_array::<COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH>()?;
            transcript.record_response_commitment(root, fiat_shamir_round_salt)?;
            transcript.derive_verifier_message()?;
        }
        reader.finish()?;
        let reencoded = transcript.checkpoint_cursor()?;
        if reencoded.canonical_bytes() != canonical_cursor_bytes
            || reencoded.digest() != expected_cursor_digest
        {
            return Err(CompactTranscriptError::WrongCheckpointCursor);
        }
        Ok(transcript)
    }

    /// Binds a durable transcript cursor to the independently decoded proof
    /// prefix that will be continued by the incremental wire assembler.
    pub(crate) fn validate_canonical_proof_prefix(
        &self,
        canonical_proof_prefix_bytes: &[u8],
    ) -> Result<(), CompactTranscriptError> {
        self.validate_canonical_proof_prefix_at_response_count(
            canonical_proof_prefix_bytes,
            self.commitment_entries.len(),
        )
    }

    /// Binds a durable transcript cursor to an independently decoded initial
    /// proof prefix whose response openings may lag their commitments.
    ///
    /// A response root and round salt enter the transcript before its verifier
    /// message, while a proper-subset opening can depend on a later verifier
    /// message. The incremental proof encoder therefore carries only the
    /// longest complete initial response prefix available at the checkpoint.
    pub(crate) fn validate_canonical_proof_prefix_at_response_count(
        &self,
        canonical_proof_prefix_bytes: &[u8],
        completed_proof_response_count: usize,
    ) -> Result<(), CompactTranscriptError> {
        if self.verifier_message_pending || self.commitment_entries.is_empty() {
            return Err(CompactTranscriptError::WrongProverPhase);
        }
        if completed_proof_response_count > self.commitment_entries.len() {
            return Err(CompactTranscriptError::WrongCheckpointCursor);
        }
        let decoded_prefix = decode_compact_proof_wire_prefix(
            self.geometry,
            canonical_proof_prefix_bytes,
            completed_proof_response_count,
        )?;
        if decoded_prefix.responses().len() != completed_proof_response_count {
            return Err(CompactTranscriptError::WrongCheckpointCursor);
        }
        for (decoded_response, entry) in decoded_prefix
            .responses()
            .iter()
            .zip(&self.commitment_entries[..completed_proof_response_count])
        {
            if decoded_response.root() != entry.root
                || decoded_response.fiat_shamir_round_salt(canonical_proof_prefix_bytes)?
                    != entry.fiat_shamir_round_salt
            {
                return Err(CompactTranscriptError::WrongCheckpointCursor);
            }
        }
        Ok(())
    }

    pub(crate) fn record_response_commitment(
        &mut self,
        root: [u8; Hash512::BYTE_LENGTH],
        fiat_shamir_round_salt: [u8; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
    ) -> Result<(), CompactTranscriptError> {
        if self.verifier_message_pending
            || self.commitment_entries.len() >= self.geometry.responses().len()
        {
            return Err(CompactTranscriptError::WrongProverPhase);
        }
        self.commitment_entries
            .push(CompactTranscriptCommitmentEntry {
                root,
                fiat_shamir_round_salt,
            });
        self.verifier_message_pending = true;
        Ok(())
    }

    pub(crate) fn derive_verifier_message(
        &mut self,
    ) -> Result<DecodedFixedUniformVerifierMessage, CompactTranscriptError> {
        if !self.verifier_message_pending {
            return Err(CompactTranscriptError::WrongProverPhase);
        }
        let response_index = self
            .commitment_entries
            .len()
            .checked_sub(1)
            .ok_or(CompactTranscriptError::WrongProverPhase)?;
        let logical_verifier_move_ordinal =
            u32::try_from(response_index).map_err(|_| CompactTranscriptError::LengthOverflow)?;
        let response_geometry = self
            .geometry
            .responses()
            .get(response_index)
            .ok_or(CompactTranscriptError::InvalidGeometry)?;
        let prefix_digest = compact_fiat_shamir_prefix_digest_from_entries(
            self.geometry,
            self.canonical_public_input_bytes,
            logical_verifier_move_ordinal,
            self.commitment_entries.iter().copied().map(Ok),
        )?;
        let verifier_message = derive_fixed_uniform_verifier_message(
            prefix_digest,
            logical_verifier_move_ordinal,
            response_geometry.verifier_message_geometry(),
        )?;
        self.verifier_message_pending = false;
        Ok(verifier_message)
    }

    pub(crate) fn finish(self) -> Result<(), CompactTranscriptError> {
        if self.verifier_message_pending
            || self.commitment_entries.len() != self.geometry.responses().len()
        {
            return Err(CompactTranscriptError::WrongProverPhase);
        }
        Ok(())
    }
}

#[cfg(test)]
struct CompactTranscriptCheckpointCursorReader<'bytes> {
    bytes: &'bytes [u8],
    offset: usize,
}

#[cfg(test)]
impl<'bytes> CompactTranscriptCheckpointCursorReader<'bytes> {
    const fn new(bytes: &'bytes [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_array<const BYTE_LENGTH: usize>(
        &mut self,
    ) -> Result<[u8; BYTE_LENGTH], CompactTranscriptError> {
        let end = self
            .offset
            .checked_add(BYTE_LENGTH)
            .ok_or(CompactTranscriptError::LengthOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CompactTranscriptError::WrongCheckpointCursor)?
            .try_into()
            .map_err(|_| CompactTranscriptError::WrongCheckpointCursor)?;
        self.offset = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, CompactTranscriptError> {
        Ok(u16::from_le_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, CompactTranscriptError> {
        Ok(u32::from_le_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, CompactTranscriptError> {
        Ok(u64::from_le_bytes(self.read_array()?))
    }

    fn finish(self) -> Result<(), CompactTranscriptError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CompactTranscriptError::WrongCheckpointCursor)
        }
    }
}

pub(crate) fn derive_compact_fiat_shamir_verifier_message(
    geometry: &CompactProofWireGeometry,
    decoded_proof: &DecodedCompactProofWire,
    canonical_proof_bytes: &[u8],
    decoded_public_input: &DecodedCompactPublicInput,
    canonical_public_input_bytes: &[u8],
    logical_verifier_move_ordinal: u32,
) -> Result<DecodedFixedUniformVerifierMessage, CompactTranscriptError> {
    let current_response_index = usize::try_from(logical_verifier_move_ordinal)
        .map_err(|_| CompactTranscriptError::LengthOverflow)?;
    let response_geometry = geometry
        .responses()
        .get(current_response_index)
        .ok_or(CompactTranscriptError::InvalidGeometry)?;
    let prefix_digest = compact_fiat_shamir_round_prefix_digest(
        geometry,
        decoded_proof,
        canonical_proof_bytes,
        decoded_public_input,
        canonical_public_input_bytes,
        logical_verifier_move_ordinal,
    )?;
    derive_fixed_uniform_verifier_message(
        prefix_digest,
        logical_verifier_move_ordinal,
        response_geometry.verifier_message_geometry(),
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
    use crate::bgv::proof_suite::compact_proof_wire::{
        CompactProofResponseWireGeometry, CompactProofResponseWireInput, CompactProofWireAssembler,
        CompactProofWireInput, CompactPublicInputBindings, CompactPublicInputWireGeometry,
        decode_compact_proof_wire, decode_compact_public_input, encode_compact_proof_wire,
        encode_compact_public_input,
    };
    use crate::bgv::proof_suite::field::{ProofBaseFieldElement, ProofChallengeExtensionElement};
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
        FixedUniformDistinctQueryGeometry, FixedUniformVerifierMessageGeometry,
    };

    fn verifier_message_geometry() -> FixedUniformVerifierMessageGeometry {
        FixedUniformVerifierMessageGeometry::new(
            1,
            0,
            1,
            vec![FixedUniformDistinctQueryGeometry::new(16, 2)],
        )
        .expect("test verifier-message geometry")
    }

    fn proof_geometry() -> CompactProofWireGeometry {
        CompactProofWireGeometry::new(vec![
            CompactProofResponseWireGeometry::new(0, 1, 0, 1, 1, verifier_message_geometry())
                .expect("first response geometry"),
            CompactProofResponseWireGeometry::new(1, 0, 1, 1, 1, verifier_message_geometry())
                .expect("second response geometry"),
        ])
        .expect("proof geometry")
    }

    fn proof_input(
        first_root_byte: u8,
        first_round_salt_byte: u8,
        second_root_byte: u8,
        second_round_salt_byte: u8,
    ) -> CompactProofWireInput {
        CompactProofWireInput::new(Vec::from(proof_responses(
            first_root_byte,
            first_round_salt_byte,
            second_root_byte,
            second_round_salt_byte,
        )))
    }

    fn proof_responses(
        first_root_byte: u8,
        first_round_salt_byte: u8,
        second_root_byte: u8,
        second_round_salt_byte: u8,
    ) -> [CompactProofResponseWireInput; 2] {
        [
            CompactProofResponseWireInput::new(
                [first_root_byte; Hash512::BYTE_LENGTH],
                [first_round_salt_byte; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
                vec![ProofBaseFieldElement::from_canonical(11).expect("base field value")],
                Vec::new(),
                vec![[0x31; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]],
                vec![[0x41; Hash512::BYTE_LENGTH]],
            ),
            CompactProofResponseWireInput::new(
                [second_root_byte; Hash512::BYTE_LENGTH],
                [second_round_salt_byte; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
                Vec::new(),
                vec![
                    ProofChallengeExtensionElement::from_canonical_coordinates([2, 3, 5, 7, 11])
                        .expect("extension field value"),
                ],
                vec![[0x32; COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH]],
                vec![[0x42; Hash512::BYTE_LENGTH]],
            ),
        ]
    }

    fn public_input(
        field_value: u64,
    ) -> (
        CompactPublicInputWireGeometry,
        CompactPublicInputBindings,
        Vec<u8>,
    ) {
        let geometry = CompactPublicInputWireGeometry::new(1, 1).expect("public geometry");
        let bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x52; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x53; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x54; Hash512::BYTE_LENGTH]),
        );
        let bytes = encode_compact_public_input(
            geometry,
            bindings,
            &[ProofBaseFieldElement::from_canonical(field_value).expect("public field value")],
        )
        .expect("public input bytes");
        (geometry, bindings, bytes)
    }

    fn round_message(
        proof_geometry: &CompactProofWireGeometry,
        proof_input: &CompactProofWireInput,
        public_field_value: u64,
        round_ordinal: u32,
    ) -> DecodedFixedUniformVerifierMessage {
        let proof_bytes =
            encode_compact_proof_wire(proof_geometry, proof_input).expect("proof bytes");
        let decoded_proof =
            decode_compact_proof_wire(proof_geometry, &proof_bytes).expect("decoded proof");
        let (public_geometry, bindings, public_bytes) = public_input(public_field_value);
        let decoded_public = decode_compact_public_input(public_geometry, bindings, &public_bytes)
            .expect("decoded public input");
        derive_compact_fiat_shamir_verifier_message(
            proof_geometry,
            &decoded_proof,
            &proof_bytes,
            &decoded_public,
            &public_bytes,
            round_ordinal,
        )
        .expect("round message")
    }

    #[test]
    fn every_round_binds_the_complete_commitment_and_salt_prefix() {
        let geometry = proof_geometry();
        let baseline_input = proof_input(0x11, 0x21, 0x12, 0x22);
        let first_message = round_message(&geometry, &baseline_input, 13, 0);
        let second_message = round_message(&geometry, &baseline_input, 13, 1);

        assert_eq!(
            first_message,
            round_message(&geometry, &proof_input(0x11, 0x21, 0x99, 0x98), 13, 0),
            "a future response is outside the first round prefix"
        );
        assert_ne!(
            second_message,
            round_message(&geometry, &proof_input(0x91, 0x21, 0x12, 0x22), 13, 1),
            "the preceding root is bound"
        );
        assert_ne!(
            second_message,
            round_message(&geometry, &proof_input(0x11, 0x81, 0x12, 0x22), 13, 1),
            "the preceding round salt is bound"
        );
        assert_ne!(
            second_message,
            round_message(&geometry, &proof_input(0x11, 0x21, 0x92, 0x22), 13, 1),
            "the current root is bound before its challenge"
        );
        assert_ne!(
            second_message,
            round_message(&geometry, &proof_input(0x11, 0x21, 0x12, 0x82), 13, 1),
            "the current round salt is bound before its challenge"
        );
        assert_ne!(
            first_message,
            round_message(&geometry, &baseline_input, 17, 0),
            "the complete canonical public input is bound"
        );
    }

    #[test]
    fn prover_transcript_matches_every_canonical_verifier_prefix_and_enforces_chronology() {
        let geometry = proof_geometry();
        let input = proof_input(0x11, 0x21, 0x12, 0x22);
        let proof_bytes = encode_compact_proof_wire(&geometry, &input).expect("proof bytes");
        let decoded_proof =
            decode_compact_proof_wire(&geometry, &proof_bytes).expect("decoded proof");
        let (public_geometry, bindings, public_bytes) = public_input(13);
        let decoded_public = decode_compact_public_input(public_geometry, bindings, &public_bytes)
            .expect("decoded public input");
        let mut prover_transcript =
            CompactProverTranscript::new(&geometry, &decoded_public, &public_bytes)
                .expect("prover transcript");

        assert_eq!(
            prover_transcript.derive_verifier_message(),
            Err(CompactTranscriptError::WrongProverPhase)
        );

        let commitments = [
            (
                [0x11; Hash512::BYTE_LENGTH],
                [0x21; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            ),
            (
                [0x12; Hash512::BYTE_LENGTH],
                [0x22; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            ),
        ];
        for (response_index, (root, round_salt)) in commitments.into_iter().enumerate() {
            prover_transcript
                .record_response_commitment(root, round_salt)
                .expect("one response commitment");
            assert_eq!(
                prover_transcript.record_response_commitment(root, round_salt),
                Err(CompactTranscriptError::WrongProverPhase)
            );
            let prover_message = prover_transcript
                .derive_verifier_message()
                .expect("one prover-side verifier message");
            let verifier_message = derive_compact_fiat_shamir_verifier_message(
                &geometry,
                &decoded_proof,
                &proof_bytes,
                &decoded_public,
                &public_bytes,
                u32::try_from(response_index).expect("response ordinal"),
            )
            .expect("one verifier-side verifier message");
            assert_eq!(prover_message, verifier_message);
            assert_eq!(
                prover_transcript.derive_verifier_message(),
                Err(CompactTranscriptError::WrongProverPhase)
            );
        }
        assert_eq!(
            prover_transcript.record_response_commitment(
                [0x31; Hash512::BYTE_LENGTH],
                [0x32; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            ),
            Err(CompactTranscriptError::WrongProverPhase)
        );
        prover_transcript.finish().expect("complete chronology");
    }

    #[test]
    fn checkpoint_cursor_reconstructs_the_exact_prefix_and_refuses_substitution() {
        let geometry = proof_geometry();
        let responses = proof_responses(0x11, 0x21, 0x12, 0x22);
        let (public_geometry, bindings, public_bytes) = public_input(13);
        let decoded_public = decode_compact_public_input(public_geometry, bindings, &public_bytes)
            .expect("decoded public input");

        let mut proof_assembler = CompactProofWireAssembler::new(&geometry).unwrap();
        proof_assembler.append_response(&responses[0]).unwrap();
        let canonical_proof_prefix = proof_assembler.canonical_prefix_bytes().to_vec();

        let mut uninterrupted =
            CompactProverTranscript::new(&geometry, &decoded_public, &public_bytes).unwrap();
        assert_eq!(
            uninterrupted.checkpoint_cursor(),
            Err(CompactTranscriptError::WrongProverPhase)
        );
        uninterrupted
            .record_response_commitment(
                [0x11; Hash512::BYTE_LENGTH],
                [0x21; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            )
            .unwrap();
        assert_eq!(
            uninterrupted.checkpoint_cursor(),
            Err(CompactTranscriptError::WrongProverPhase)
        );
        let first_message = uninterrupted.derive_verifier_message().unwrap();
        let cursor = uninterrupted.checkpoint_cursor().unwrap();
        assert_eq!(uninterrupted.completed_response_count(), 1);
        assert_eq!(
            cursor.canonical_bytes().len(),
            COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_HEADER_BYTE_LENGTH
                + COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_ENTRY_BYTE_LENGTH
        );
        assert!(
            cursor.canonical_bytes().len()
                <= MAXIMUM_COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_BYTE_LENGTH
        );
        uninterrupted
            .validate_canonical_proof_prefix(&canonical_proof_prefix)
            .unwrap();

        let mut restored = CompactProverTranscript::restore_from_checkpoint_cursor(
            &geometry,
            &decoded_public,
            &public_bytes,
            cursor.canonical_bytes(),
            cursor.digest(),
        )
        .unwrap();
        assert_eq!(restored.completed_response_count(), 1);
        restored
            .validate_canonical_proof_prefix(&canonical_proof_prefix)
            .unwrap();
        restored
            .record_response_commitment(
                [0x12; Hash512::BYTE_LENGTH],
                [0x22; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            )
            .unwrap();
        uninterrupted
            .record_response_commitment(
                [0x12; Hash512::BYTE_LENGTH],
                [0x22; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            )
            .unwrap();
        let restored_second_message = restored.derive_verifier_message().unwrap();
        let uninterrupted_second_message = uninterrupted.derive_verifier_message().unwrap();
        assert_eq!(restored_second_message, uninterrupted_second_message);
        assert_ne!(
            first_message, restored_second_message,
            "the second verifier message must not collapse to the first"
        );

        let mut substituted = cursor.canonical_bytes().to_vec();
        substituted[COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_HEADER_BYTE_LENGTH + size_of::<u32>()] ^=
            1;
        assert_eq!(
            CompactProverTranscript::restore_from_checkpoint_cursor(
                &geometry,
                &decoded_public,
                &public_bytes,
                &substituted,
                cursor.digest(),
            )
            .map(|_| ()),
            Err(CompactTranscriptError::CheckpointCursorDigestMismatch)
        );

        let mut reordered = cursor.canonical_bytes().to_vec();
        reordered[COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_HEADER_BYTE_LENGTH
            ..COMPACT_TRANSCRIPT_CHECKPOINT_CURSOR_HEADER_BYTE_LENGTH + size_of::<u32>()]
            .copy_from_slice(&1_u32.to_le_bytes());
        let reordered_digest = compact_transcript_checkpoint_cursor_digest(&reordered);
        assert_eq!(
            CompactProverTranscript::restore_from_checkpoint_cursor(
                &geometry,
                &decoded_public,
                &public_bytes,
                &reordered,
                reordered_digest,
            )
            .map(|_| ()),
            Err(CompactTranscriptError::WrongCheckpointCursor)
        );

        let truncated = &cursor.canonical_bytes()[..cursor.canonical_bytes().len() - 1];
        assert_eq!(
            CompactProverTranscript::restore_from_checkpoint_cursor(
                &geometry,
                &decoded_public,
                &public_bytes,
                truncated,
                compact_transcript_checkpoint_cursor_digest(truncated),
            )
            .map(|_| ()),
            Err(CompactTranscriptError::WrongCheckpointCursor)
        );
        let mut trailing = cursor.canonical_bytes().to_vec();
        trailing.push(0);
        let trailing_digest = compact_transcript_checkpoint_cursor_digest(&trailing);
        assert_eq!(
            CompactProverTranscript::restore_from_checkpoint_cursor(
                &geometry,
                &decoded_public,
                &public_bytes,
                &trailing,
                trailing_digest,
            )
            .map(|_| ()),
            Err(CompactTranscriptError::WrongCheckpointCursor)
        );

        let (other_public_geometry, other_bindings, other_public_bytes) = public_input(17);
        let other_decoded_public =
            decode_compact_public_input(other_public_geometry, other_bindings, &other_public_bytes)
                .unwrap();
        assert_eq!(
            CompactProverTranscript::restore_from_checkpoint_cursor(
                &geometry,
                &other_decoded_public,
                &other_public_bytes,
                cursor.canonical_bytes(),
                cursor.digest(),
            )
            .map(|_| ()),
            Err(CompactTranscriptError::WrongCheckpointCursor)
        );

        let alternate_responses = proof_responses(0x91, 0x21, 0x12, 0x22);
        let mut alternate_assembler = CompactProofWireAssembler::new(&geometry).unwrap();
        alternate_assembler
            .append_response(&alternate_responses[0])
            .unwrap();
        let first_boundary = CompactProverTranscript::restore_from_checkpoint_cursor(
            &geometry,
            &decoded_public,
            &public_bytes,
            cursor.canonical_bytes(),
            cursor.digest(),
        )
        .unwrap();
        assert_eq!(
            first_boundary
                .validate_canonical_proof_prefix(alternate_assembler.canonical_prefix_bytes(),),
            Err(CompactTranscriptError::WrongCheckpointCursor)
        );
    }

    #[test]
    fn prover_transcript_refuses_incomplete_chronology() {
        let geometry = proof_geometry();
        let (public_geometry, bindings, public_bytes) = public_input(13);
        let decoded_public = decode_compact_public_input(public_geometry, bindings, &public_bytes)
            .expect("decoded public input");
        let mut pending = CompactProverTranscript::new(&geometry, &decoded_public, &public_bytes)
            .expect("pending prover transcript");
        pending
            .record_response_commitment(
                [0x11; Hash512::BYTE_LENGTH],
                [0x21; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            )
            .expect("first response commitment");
        assert_eq!(
            pending.finish(),
            Err(CompactTranscriptError::WrongProverPhase)
        );

        let incomplete = CompactProverTranscript::new(&geometry, &decoded_public, &public_bytes)
            .expect("incomplete prover transcript");
        assert_eq!(
            incomplete.finish(),
            Err(CompactTranscriptError::WrongProverPhase)
        );
    }

    #[test]
    fn prefix_geometry_is_exact_and_rejects_missing_rounds() {
        let geometry = proof_geometry();
        let input = proof_input(0x11, 0x21, 0x12, 0x22);
        let proof_bytes = encode_compact_proof_wire(&geometry, &input).expect("proof bytes");
        let decoded_proof =
            decode_compact_proof_wire(&geometry, &proof_bytes).expect("decoded proof");
        let (public_geometry, bindings, public_bytes) = public_input(13);
        let decoded_public = decode_compact_public_input(public_geometry, bindings, &public_bytes)
            .expect("decoded public input");

        assert_eq!(compact_vector_commitment_oracle_identifier(0), Ok(1));
        assert_eq!(compact_vector_commitment_oracle_identifier(1), Ok(2));
        assert_eq!(
            compact_vector_commitment_oracle_identifier(u32::MAX),
            Err(CompactTranscriptError::LengthOverflow)
        );
        assert_eq!(
            compact_fiat_shamir_prefix_payload_byte_length(public_bytes.len(), 2),
            Ok(size_of::<u64>() + public_bytes.len() + 2 * COMMITMENT_PREFIX_ENTRY_BYTE_LENGTH)
        );
        assert_eq!(
            compact_fiat_shamir_prefix_payload_byte_length(public_bytes.len(), 0),
            Err(CompactTranscriptError::InvalidGeometry)
        );
        assert_eq!(
            derive_compact_fiat_shamir_verifier_message(
                &geometry,
                &decoded_proof,
                &proof_bytes,
                &decoded_public,
                &public_bytes,
                2,
            ),
            Err(CompactTranscriptError::InvalidGeometry)
        );
    }
}
