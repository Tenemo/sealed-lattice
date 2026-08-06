//! Canonical Fiat-Shamir transcript for the compact ring-vector construction.
//!
//! CDHZ Construction 11.7 derives round `i` from the explicit instance, every
//! vector-commitment pair through `i`, and every independent round salt
//! through `i`. The compact construction fixes commitment-oracle identifier
//! `i + 1`, so the identifier is verifier-derived and is not transported.
//! This module streams the complete canonical public input and ordered prefix
//! without allocating a second copy of either byte string.
//!
//! The resulting 512-bit prefix digest feeds the fixed-width verifier-message
//! seed and predecessor-linked block schedule. That concrete multi-call
//! SHAKE256 graph still needs its separate emitted-byte QROM correspondence;
//! this module does not equate the graph with one ideal variable-output call.

use std::mem::size_of;

use super::compact_proof_wire::COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH;
use super::compact_proof_wire::{
    CompactProofWireError, CompactProofWireGeometry, DecodedCompactProofWire,
    DecodedCompactPublicInput,
};
use super::fixed_uniform_verifier_message::{
    DecodedFixedUniformVerifierMessage, FixedUniformVerifierMessageError,
    derive_fixed_uniform_verifier_message,
};
use crate::foundation::{
    CanonicalItem, Hash512, StreamingFoundationHashError, StreamingFoundationTupleHash512,
};

const COMPACT_FIAT_SHAMIR_PREFIX_DOMAIN: &str =
    "sealed-lattice/proof/compact-fiat-shamir-prefix/v1";
const COMPACT_FIAT_SHAMIR_PREFIX_VERSION: u16 = 1;
const COMMITMENT_PREFIX_ENTRY_BYTE_LENGTH: usize = size_of::<u32>() + 2 * Hash512::BYTE_LENGTH;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactTranscriptError {
    InvalidGeometry,
    LengthOverflow,
    AllocationLimitExceeded,
    WrongProverPhase,
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
            CanonicalItem::unsigned16(geometry.packing_factor()),
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
pub(crate) struct CompactProverTranscript<'input> {
    geometry: &'input CompactProofWireGeometry,
    canonical_public_input_bytes: &'input [u8],
    commitment_entries: Vec<CompactTranscriptCommitmentEntry>,
    verifier_message_pending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CompactProverTranscriptNativeMemoryGeometry {
    state_inline_byte_length: u64,
    commitment_entry_heap_byte_length: u64,
    resident_owned_byte_length: u64,
}

impl CompactProverTranscriptNativeMemoryGeometry {
    pub(crate) fn derive(
        geometry: &CompactProofWireGeometry,
    ) -> Result<Self, CompactTranscriptError> {
        if geometry.responses().is_empty() {
            return Err(CompactTranscriptError::InvalidGeometry);
        }
        let state_inline_byte_length = u64::try_from(size_of::<CompactProverTranscript<'static>>())
            .map_err(|_| CompactTranscriptError::LengthOverflow)?;
        let commitment_entry_heap_byte_length = u64::try_from(geometry.responses().len())
            .ok()
            .and_then(|entry_count| {
                u64::try_from(size_of::<CompactTranscriptCommitmentEntry>())
                    .ok()
                    .and_then(|entry_byte_length| entry_count.checked_mul(entry_byte_length))
            })
            .ok_or(CompactTranscriptError::LengthOverflow)?;
        let resident_owned_byte_length = state_inline_byte_length
            .checked_add(commitment_entry_heap_byte_length)
            .ok_or(CompactTranscriptError::LengthOverflow)?;
        Ok(Self {
            state_inline_byte_length,
            commitment_entry_heap_byte_length,
            resident_owned_byte_length,
        })
    }

    pub(crate) const fn state_inline_byte_length(self) -> u64 {
        self.state_inline_byte_length
    }

    pub(crate) const fn commitment_entry_heap_byte_length(self) -> u64 {
        self.commitment_entry_heap_byte_length
    }

    pub(crate) const fn resident_owned_byte_length(self) -> u64 {
        self.resident_owned_byte_length
    }
}

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
        CompactProofResponseWireGeometry, CompactProofResponseWireInput, CompactProofWireInput,
        CompactPublicInputBindings, CompactPublicInputWireGeometry, decode_compact_proof_wire,
        decode_compact_public_input, encode_compact_proof_wire, encode_compact_public_input,
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
        CompactProofWireGeometry::new(
            4,
            vec![
                CompactProofResponseWireGeometry::new(0, 1, 0, 1, 1, verifier_message_geometry())
                    .expect("first response geometry"),
                CompactProofResponseWireGeometry::new(1, 0, 1, 1, 1, verifier_message_geometry())
                    .expect("second response geometry"),
            ],
        )
        .expect("proof geometry")
    }

    fn proof_input(
        first_root_byte: u8,
        first_round_salt_byte: u8,
        second_root_byte: u8,
        second_round_salt_byte: u8,
    ) -> CompactProofWireInput {
        CompactProofWireInput::new(vec![
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
        ])
    }

    fn public_input(
        field_value: u64,
    ) -> (
        CompactPublicInputWireGeometry,
        CompactPublicInputBindings,
        Vec<u8>,
    ) {
        let geometry = CompactPublicInputWireGeometry::new(4, 1, 1).expect("public geometry");
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
            decode_compact_proof_wire(proof_geometry, &proof_bytes, proof_bytes.len())
                .expect("decoded proof");
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
        let decoded_proof = decode_compact_proof_wire(&geometry, &proof_bytes, proof_bytes.len())
            .expect("decoded proof");
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
    fn prover_transcript_refuses_incomplete_chronology_and_has_exact_native_storage() {
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

        let memory = CompactProverTranscriptNativeMemoryGeometry::derive(&geometry)
            .expect("native transcript memory geometry");
        assert_eq!(
            memory.commitment_entry_heap_byte_length(),
            2 * u64::try_from(size_of::<CompactTranscriptCommitmentEntry>()).expect("entry size")
        );
        assert_eq!(
            memory.resident_owned_byte_length(),
            memory.state_inline_byte_length() + memory.commitment_entry_heap_byte_length()
        );
    }

    #[test]
    fn prefix_geometry_is_exact_and_rejects_missing_rounds() {
        let geometry = proof_geometry();
        let input = proof_input(0x11, 0x21, 0x12, 0x22);
        let proof_bytes = encode_compact_proof_wire(&geometry, &input).expect("proof bytes");
        let decoded_proof = decode_compact_proof_wire(&geometry, &proof_bytes, proof_bytes.len())
            .expect("decoded proof");
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
