//! Durable response-boundary state for compact proof generation.
//!
//! Response commitments enter Fiat-Shamir chronology before their verifier
//! messages, but a proper-subset opening may depend on a later message. The
//! canonical proof encoder can therefore trail the transcript. This module
//! derives that lag from verifier-owned Merkle geometry. The release contract
//! retains the response-count schedule, transcript cursor, and encoded-prefix
//! checkpoint binding used by release compact generation.

use super::compact_proof_wire::CompactProofWireAssembler;
use super::compact_proof_wire::CompactProofWireGeometry;
use super::compact_response_merkle::{
    CompactResponseMerkleError, CompactResponseMerkleGeometry, CompactResponseQuerySchedule,
};
use super::compact_transcript::{CompactProverTranscript, CompactTranscriptError};
use super::prover::CommonProofGenerationCheckpointBoundary;
use crate::foundation::Hash512;
use crate::hashing::StreamingHash512;

const COMPACT_RESPONSE_CHECKPOINT_SCHEDULE_DIGEST_DOMAIN: &str =
    "sealed-lattice/proof/compact-response-checkpoint-schedule/v1";
const COMPACT_RESPONSE_CHECKPOINT_COMMITTED_STATE_DIGEST_DOMAIN: &str =
    "sealed-lattice/proof/compact-response-checkpoint-committed-state/v2";
const COMPACT_RESPONSE_CHECKPOINT_POSITION_VERSION: u8 = 1;
const COMPACT_RESPONSE_CHECKPOINT_POSITION_STAGE: u8 = 1;
const MAXIMUM_COMPACT_CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTE_LENGTH: usize = 16 * 1_024;

pub(crate) const fn compact_checkpoint_binding_domains() -> [&'static str; 2] {
    [
        COMPACT_RESPONSE_CHECKPOINT_SCHEDULE_DIGEST_DOMAIN,
        COMPACT_RESPONSE_CHECKPOINT_COMMITTED_STATE_DIGEST_DOMAIN,
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompactGenerationCheckpointError {
    InvalidGeometry,
    InvalidPrivateRandomnessCursor,
    LengthOverflow,
    WrongResponseBoundary,
    ResponseMerkle(CompactResponseMerkleError),
    Transcript(CompactTranscriptError),
}

impl From<CompactResponseMerkleError> for CompactGenerationCheckpointError {
    fn from(error: CompactResponseMerkleError) -> Self {
        Self::ResponseMerkle(error)
    }
}

impl From<CompactTranscriptError> for CompactGenerationCheckpointError {
    fn from(error: CompactTranscriptError) -> Self {
        Self::Transcript(error)
    }
}

/// Verifier-derived count of canonical response sections available after each
/// logical verifier move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompactResponseCheckpointSchedule {
    completed_proof_response_counts: Vec<u32>,
    dependency_digest: [u8; Hash512::BYTE_LENGTH],
}

impl CompactResponseCheckpointSchedule {
    pub(crate) fn derive(
        proof_wire_geometry: &CompactProofWireGeometry,
        response_merkle_geometries: &[CompactResponseMerkleGeometry],
    ) -> Result<Self, CompactGenerationCheckpointError> {
        CompactResponseQuerySchedule::validate_registry(
            response_merkle_geometries,
            proof_wire_geometry.responses(),
        )?;
        let response_count = response_merkle_geometries.len();
        if response_count == 0 || response_count != proof_wire_geometry.responses().len() {
            return Err(CompactGenerationCheckpointError::InvalidGeometry);
        }
        let response_count_u32 = u32::try_from(response_count)
            .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?;

        let mut last_query_verifier_move_ordinals = Vec::new();
        last_query_verifier_move_ordinals
            .try_reserve_exact(response_count)
            .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?;
        let mut schedule_hasher = {
            let digest_part_count = u64::try_from(response_count)
                .ok()
                .and_then(|count| count.checked_add(1))
                .ok_or(CompactGenerationCheckpointError::LengthOverflow)?;
            let mut hasher = StreamingHash512::new(
                COMPACT_RESPONSE_CHECKPOINT_SCHEDULE_DIGEST_DOMAIN,
                digest_part_count,
            );
            hasher.absorb_part(&response_count_u32.to_le_bytes());
            hasher
        };
        for (response_index, merkle_geometry) in response_merkle_geometries.iter().enumerate() {
            let response_ordinal = u32::try_from(response_index)
                .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?;
            let last_query_verifier_move_ordinal =
                merkle_geometry.last_query_verifier_move_ordinal();
            if merkle_geometry.response_ordinal() != response_ordinal
                || last_query_verifier_move_ordinal < response_ordinal
                || last_query_verifier_move_ordinal >= response_count_u32
            {
                return Err(CompactGenerationCheckpointError::InvalidGeometry);
            }
            let mut dependency = [0_u8; 8];
            dependency[..4].copy_from_slice(&response_ordinal.to_le_bytes());
            dependency[4..].copy_from_slice(&last_query_verifier_move_ordinal.to_le_bytes());
            schedule_hasher.absorb_part(&dependency);
            last_query_verifier_move_ordinals.push(last_query_verifier_move_ordinal);
        }

        let mut completed_proof_response_counts = Vec::new();
        completed_proof_response_counts
            .try_reserve_exact(response_count)
            .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?;
        let mut next_unencoded_response_index = 0_usize;
        for verifier_move_index in 0..response_count {
            let verifier_move_ordinal = u32::try_from(verifier_move_index)
                .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?;
            while last_query_verifier_move_ordinals
                .get(next_unencoded_response_index)
                .is_some_and(|last_query_ordinal| *last_query_ordinal <= verifier_move_ordinal)
            {
                next_unencoded_response_index = next_unencoded_response_index
                    .checked_add(1)
                    .ok_or(CompactGenerationCheckpointError::LengthOverflow)?;
            }
            if next_unencoded_response_index
                > verifier_move_index
                    .checked_add(1)
                    .ok_or(CompactGenerationCheckpointError::LengthOverflow)?
            {
                return Err(CompactGenerationCheckpointError::InvalidGeometry);
            }
            completed_proof_response_counts.push(
                u32::try_from(next_unencoded_response_index)
                    .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?,
            );
        }
        if next_unencoded_response_index != response_count {
            return Err(CompactGenerationCheckpointError::InvalidGeometry);
        }

        Ok(Self {
            completed_proof_response_counts,
            dependency_digest: schedule_hasher.finalize(),
        })
    }

    pub(crate) fn total_response_count(&self) -> usize {
        self.completed_proof_response_counts.len()
    }

    pub(crate) const fn checkpoint_schedule_digest(&self) -> Hash512 {
        Hash512::from_bytes(self.dependency_digest)
    }

    pub(crate) fn completed_proof_response_counts(&self) -> &[u32] {
        &self.completed_proof_response_counts
    }

    #[cfg(test)]
    pub(crate) fn lagging_checkpoint_count(&self) -> usize {
        self.completed_proof_response_counts
            .iter()
            .enumerate()
            .filter(|(verifier_move_index, completed_proof_response_count)| {
                usize::try_from(**completed_proof_response_count).ok()
                    != verifier_move_index.checked_add(1)
            })
            .count()
    }

    #[cfg(test)]
    pub(crate) fn maximum_pending_proof_response_count(&self) -> usize {
        self.completed_proof_response_counts
            .iter()
            .enumerate()
            .filter_map(|(verifier_move_index, completed_proof_response_count)| {
                verifier_move_index
                    .checked_add(1)?
                    .checked_sub(usize::try_from(*completed_proof_response_count).ok()?)
            })
            .max()
            .unwrap_or(0)
    }

    pub(crate) fn completed_proof_response_count(
        &self,
        completed_transcript_response_count: usize,
    ) -> Result<usize, CompactGenerationCheckpointError> {
        let verifier_move_index = completed_transcript_response_count
            .checked_sub(1)
            .ok_or(CompactGenerationCheckpointError::WrongResponseBoundary)?;
        self.completed_proof_response_counts
            .get(verifier_move_index)
            .copied()
            .ok_or(CompactGenerationCheckpointError::WrongResponseBoundary)
            .and_then(|count| {
                usize::try_from(count).map_err(|_| CompactGenerationCheckpointError::LengthOverflow)
            })
    }
}

/// Constructs the common checkpoint boundary consumed by the authenticated
/// generation host. The committed state additionally binds the compact
/// construction's private-randomness cursor, including state owned below the
/// common private-coin source. The host separately binds the suite and action
/// context, proof attempt and source authority, the common private-coin cursor
/// manifest, external object identities and digests, and deletion state.
pub(crate) fn compact_response_generation_checkpoint_boundary(
    checkpoint_schedule: &CompactResponseCheckpointSchedule,
    prover_transcript: &CompactProverTranscript,
    proof_wire_assembler: &CompactProofWireAssembler,
    canonical_construction_private_randomness_cursor_bytes: &[u8],
) -> Result<CommonProofGenerationCheckpointBoundary, CompactGenerationCheckpointError> {
    if canonical_construction_private_randomness_cursor_bytes.is_empty()
        || canonical_construction_private_randomness_cursor_bytes.len()
            > MAXIMUM_COMPACT_CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTE_LENGTH
    {
        return Err(CompactGenerationCheckpointError::InvalidPrivateRandomnessCursor);
    }
    let completed_transcript_response_count = prover_transcript.completed_response_count();
    if prover_transcript.total_response_count() != checkpoint_schedule.total_response_count() {
        return Err(CompactGenerationCheckpointError::InvalidGeometry);
    }
    let completed_proof_response_count =
        checkpoint_schedule.completed_proof_response_count(completed_transcript_response_count)?;
    if proof_wire_assembler.completed_response_count() != completed_proof_response_count {
        return Err(CompactGenerationCheckpointError::WrongResponseBoundary);
    }
    prover_transcript.validate_canonical_proof_prefix_at_response_count(
        proof_wire_assembler.canonical_prefix_bytes(),
        completed_proof_response_count,
    )?;

    let verifier_move_ordinal = u32::try_from(
        completed_transcript_response_count
            .checked_sub(1)
            .ok_or(CompactGenerationCheckpointError::WrongResponseBoundary)?,
    )
    .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?;
    let completed_transcript_response_count_u32 =
        u32::try_from(completed_transcript_response_count)
            .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?;
    let completed_proof_response_count_u32 = u32::try_from(completed_proof_response_count)
        .map_err(|_| CompactGenerationCheckpointError::LengthOverflow)?;
    let mut position = [0_u8; 16];
    position[0] = COMPACT_RESPONSE_CHECKPOINT_POSITION_VERSION;
    position[1] = COMPACT_RESPONSE_CHECKPOINT_POSITION_STAGE;
    position[4..8].copy_from_slice(&verifier_move_ordinal.to_le_bytes());
    position[8..12].copy_from_slice(&completed_transcript_response_count_u32.to_le_bytes());
    position[12..16].copy_from_slice(&completed_proof_response_count_u32.to_le_bytes());

    let transcript_cursor = prover_transcript.checkpoint_cursor()?;
    let transcript_cursor_digest = transcript_cursor.digest();
    let mut committed_state_hasher =
        StreamingHash512::new(COMPACT_RESPONSE_CHECKPOINT_COMMITTED_STATE_DIGEST_DOMAIN, 5);
    committed_state_hasher.absorb_part(&position);
    committed_state_hasher.absorb_part(&checkpoint_schedule.dependency_digest);
    committed_state_hasher.absorb_part(transcript_cursor.canonical_bytes());
    committed_state_hasher.absorb_part(proof_wire_assembler.canonical_prefix_bytes());
    committed_state_hasher.absorb_part(canonical_construction_private_randomness_cursor_bytes);
    let committed_state_digest = committed_state_hasher.finalize();

    Ok(CommonProofGenerationCheckpointBoundary::new(
        verifier_move_ordinal,
        position,
        committed_state_digest,
    )
    .with_canonical_transcript_cursor(
        transcript_cursor.into_canonical_bytes(),
        transcript_cursor_digest,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bgv::proof_suite::COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH;
    use crate::bgv::proof_suite::compact_proof_wire::{
        COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireGeometry,
        CompactProofResponseWireInput, CompactPublicInputBindings, CompactPublicInputWireGeometry,
        PROOF_FIXED_HEADER_BYTE_LENGTH, decode_compact_public_input, encode_compact_public_input,
    };
    use crate::bgv::proof_suite::compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValueKind,
        CompactResponseQuerySelection,
    };
    use crate::bgv::proof_suite::field::ProofBaseFieldElement;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
        FixedUniformDistinctQueryGeometry, FixedUniformVerifierMessageGeometry,
    };

    const RESPONSE_COUNT: usize = 4;
    const CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES: &[u8] =
        b"canonical compact construction private-randomness cursor";

    fn verifier_message_geometry(
        logical_verifier_move_ordinal: u32,
    ) -> FixedUniformVerifierMessageGeometry {
        let distinct_query_groups = if logical_verifier_move_ordinal == 3 {
            vec![FixedUniformDistinctQueryGeometry::new(2, 1)]
        } else {
            Vec::new()
        };
        FixedUniformVerifierMessageGeometry::new(0, 0, 1, distinct_query_groups)
            .expect("small verifier-message geometry")
    }

    fn proof_wire_geometry() -> CompactProofWireGeometry {
        CompactProofWireGeometry::new(
            (0_u32..u32::try_from(RESPONSE_COUNT).expect("small response count"))
                .map(|response_ordinal| {
                    CompactProofResponseWireGeometry::new(
                        response_ordinal,
                        1,
                        0,
                        1,
                        u64::from(response_ordinal == 1),
                        verifier_message_geometry(response_ordinal),
                    )
                    .expect("small proof response geometry")
                })
                .collect(),
        )
        .expect("small proof wire geometry")
    }

    fn response_merkle_geometries() -> Vec<CompactResponseMerkleGeometry> {
        (0_u32..u32::try_from(RESPONSE_COUNT).expect("small response count"))
            .map(|response_ordinal| {
                let (leaf_count, query_selection) = if response_ordinal == 1 {
                    (
                        2,
                        CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                            logical_verifier_move_ordinal: 3,
                            distinct_query_group_ordinal: 0,
                        },
                    )
                } else {
                    (1, CompactResponseQuerySelection::EveryLeaf)
                };
                CompactResponseMerkleGeometry::new(
                    response_ordinal,
                    vec![CompactResponseComponentGeometry::new(
                        0,
                        leaf_count,
                        1,
                        query_selection,
                        CompactResponseLeafValueKind::BaseField,
                        1,
                    )],
                )
                .expect("small response Merkle geometry")
            })
            .collect()
    }

    fn response_input(
        response_ordinal: usize,
        root_byte: u8,
        base_field_value: u64,
    ) -> CompactProofResponseWireInput {
        CompactProofResponseWireInput::new(
            [root_byte; Hash512::BYTE_LENGTH],
            [0x21 + u8::try_from(response_ordinal).expect("small response ordinal");
                COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            vec![
                ProofBaseFieldElement::from_canonical(base_field_value)
                    .expect("small canonical field value"),
            ],
            Vec::new(),
            vec![
                [0x31 + u8::try_from(response_ordinal).expect("small response ordinal");
                    COMMON_PROOF_SECRET_LEAF_SALT_BYTE_LENGTH],
            ],
            if response_ordinal == 1 {
                vec![[0x41; Hash512::BYTE_LENGTH]]
            } else {
                Vec::new()
            },
        )
    }

    fn response_inputs() -> Vec<CompactProofResponseWireInput> {
        (0..RESPONSE_COUNT)
            .map(|response_ordinal| {
                response_input(
                    response_ordinal,
                    0x11 + u8::try_from(response_ordinal).expect("small response ordinal"),
                    11 + u64::try_from(response_ordinal).expect("small response ordinal"),
                )
            })
            .collect()
    }

    fn public_input() -> (
        CompactPublicInputWireGeometry,
        CompactPublicInputBindings,
        Vec<u8>,
    ) {
        let geometry =
            CompactPublicInputWireGeometry::new(1, 1).expect("small public-input geometry");
        let bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x51; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x52; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x53; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x54; Hash512::BYTE_LENGTH]),
        );
        let canonical_bytes = encode_compact_public_input(
            geometry,
            bindings,
            &[ProofBaseFieldElement::from_canonical(13)
                .expect("small canonical public-input value")],
        )
        .expect("canonical public-input bytes");
        (geometry, bindings, canonical_bytes)
    }

    fn record_response_and_derive_message(
        transcript: &mut CompactProverTranscript,
        response_ordinal: usize,
    ) {
        transcript
            .record_response_commitment(
                [0x11 + u8::try_from(response_ordinal).expect("small response ordinal");
                    Hash512::BYTE_LENGTH],
                [0x21 + u8::try_from(response_ordinal).expect("small response ordinal");
                    COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            )
            .expect("record response commitment");
        transcript
            .derive_verifier_message()
            .expect("derive verifier message");
    }

    fn append_available_responses(
        assembler: &mut CompactProofWireAssembler,
        responses: &[CompactProofResponseWireInput],
        verifier_move_ordinal: usize,
    ) {
        match verifier_move_ordinal {
            0 => assembler
                .append_response(&responses[0])
                .expect("append immediately available first response"),
            3 => {
                for response in &responses[1..] {
                    assembler
                        .append_response(response)
                        .expect("append released canonical response suffix");
                }
            }
            1 | 2 => {}
            _ => panic!("unexpected verifier move"),
        }
    }

    #[test]
    fn checkpoint_schedule_derives_the_longest_available_canonical_prefix() {
        let proof_geometry = proof_wire_geometry();
        let merkle_geometries = response_merkle_geometries();
        let schedule =
            CompactResponseCheckpointSchedule::derive(&proof_geometry, &merkle_geometries)
                .expect("checkpoint schedule");
        assert_eq!(schedule.total_response_count(), RESPONSE_COUNT);
        assert_eq!(
            (1..=RESPONSE_COUNT)
                .map(|completed_transcript_response_count| schedule
                    .completed_proof_response_count(completed_transcript_response_count)
                    .expect("one checkpoint count"))
                .collect::<Vec<_>>(),
            vec![1, 1, 1, 4]
        );
        assert_eq!(
            schedule.completed_proof_response_count(0),
            Err(CompactGenerationCheckpointError::WrongResponseBoundary)
        );
        assert_eq!(
            schedule.completed_proof_response_count(RESPONSE_COUNT + 1),
            Err(CompactGenerationCheckpointError::WrongResponseBoundary)
        );

        let mut reordered_merkle_geometries = merkle_geometries.clone();
        reordered_merkle_geometries.swap(0, 1);
        assert!(matches!(
            CompactResponseCheckpointSchedule::derive(
                &proof_geometry,
                &reordered_merkle_geometries
            ),
            Err(CompactGenerationCheckpointError::ResponseMerkle(
                CompactResponseMerkleError::InvalidGeometry
            ))
        ));

        let mut premature_query_geometries = merkle_geometries;
        premature_query_geometries[1] = CompactResponseMerkleGeometry::new(
            1,
            vec![CompactResponseComponentGeometry::new(
                0,
                2,
                1,
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal: 2,
                    distinct_query_group_ordinal: 0,
                },
                CompactResponseLeafValueKind::BaseField,
                1,
            )],
        )
        .expect("locally valid premature query geometry");
        assert!(matches!(
            CompactResponseCheckpointSchedule::derive(&proof_geometry, &premature_query_geometries),
            Err(CompactGenerationCheckpointError::ResponseMerkle(
                CompactResponseMerkleError::InvalidOpeningIndices
            ))
        ));
    }

    #[test]
    fn checkpoint_boundary_reconstructs_exact_lagging_transcript_and_wire_state() {
        let proof_geometry = proof_wire_geometry();
        let schedule = CompactResponseCheckpointSchedule::derive(
            &proof_geometry,
            &response_merkle_geometries(),
        )
        .expect("checkpoint schedule");
        let responses = response_inputs();
        let (public_geometry, public_bindings, public_bytes) = public_input();
        let decoded_public_input =
            decode_compact_public_input(public_geometry, public_bindings, &public_bytes)
                .expect("decoded public input");
        let mut transcript =
            CompactProverTranscript::new(&proof_geometry, &decoded_public_input, &public_bytes)
                .expect("prover transcript");
        let mut assembler =
            CompactProofWireAssembler::new(&proof_geometry).expect("proof assembler");
        let mut boundaries = Vec::new();
        let mut third_move_prefix = Vec::new();

        for verifier_move_ordinal in 0..RESPONSE_COUNT {
            record_response_and_derive_message(&mut transcript, verifier_move_ordinal);
            append_available_responses(&mut assembler, &responses, verifier_move_ordinal);
            let boundary = compact_response_generation_checkpoint_boundary(
                &schedule,
                &transcript,
                &assembler,
                CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
            )
            .expect("response checkpoint boundary");
            assert_eq!(
                boundary.safe_boundary_ordinal(),
                u32::try_from(verifier_move_ordinal).expect("small verifier move")
            );
            assert_eq!(boundary.position()[0], 1);
            assert_eq!(boundary.position()[1], 1);
            assert_eq!(
                u32::from_le_bytes(boundary.position()[8..12].try_into().unwrap()),
                u32::try_from(verifier_move_ordinal + 1).expect("small response count")
            );
            assert_eq!(
                u32::from_le_bytes(boundary.position()[12..16].try_into().unwrap()),
                u32::try_from(assembler.completed_response_count())
                    .expect("small proof response count")
            );
            if verifier_move_ordinal == 2 {
                third_move_prefix = assembler.canonical_prefix_bytes().to_vec();
            }
            boundaries.push(boundary);
        }
        assert_eq!(assembler.completed_response_count(), RESPONSE_COUNT);
        assert_ne!(boundaries[0], boundaries[1]);
        assert_ne!(boundaries[1], boundaries[2]);
        assert_ne!(
            boundaries[1].committed_state_digest(),
            boundaries[2].committed_state_digest(),
            "the same proof prefix at different transcript positions must not share a checkpoint"
        );

        let retained_boundary = &boundaries[2];
        let restored_transcript = CompactProverTranscript::restore_from_checkpoint_cursor(
            &proof_geometry,
            &decoded_public_input,
            &public_bytes,
            retained_boundary.canonical_transcript_cursor_bytes(),
            retained_boundary
                .canonical_transcript_cursor_digest()
                .expect("checkpoint carries transcript cursor digest"),
        )
        .expect("restore transcript cursor");
        let restored_assembler = CompactProofWireAssembler::restore_from_canonical_prefix(
            &proof_geometry,
            &third_move_prefix,
            1,
        )
        .expect("restore lagging proof prefix");
        assert_eq!(
            compact_response_generation_checkpoint_boundary(
                &schedule,
                &restored_transcript,
                &restored_assembler,
                CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
            )
            .expect("reconstructed checkpoint boundary"),
            retained_boundary.clone()
        );
    }

    #[test]
    fn header_only_checkpoint_is_canonical_when_the_first_opening_waits() {
        let first_message_geometry =
            FixedUniformVerifierMessageGeometry::new(0, 0, 1, Vec::new()).unwrap();
        let second_message_geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            1,
            vec![FixedUniformDistinctQueryGeometry::new(2, 1)],
        )
        .unwrap();
        let proof_geometry = CompactProofWireGeometry::new(vec![
            CompactProofResponseWireGeometry::new(0, 1, 0, 1, 1, first_message_geometry).unwrap(),
            CompactProofResponseWireGeometry::new(1, 1, 0, 1, 0, second_message_geometry).unwrap(),
        ])
        .unwrap();
        let merkle_geometries = vec![
            CompactResponseMerkleGeometry::new(
                0,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    2,
                    1,
                    CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                        logical_verifier_move_ordinal: 1,
                        distinct_query_group_ordinal: 0,
                    },
                    CompactResponseLeafValueKind::BaseField,
                    1,
                )],
            )
            .unwrap(),
            CompactResponseMerkleGeometry::new(
                1,
                vec![CompactResponseComponentGeometry::new(
                    0,
                    1,
                    1,
                    CompactResponseQuerySelection::EveryLeaf,
                    CompactResponseLeafValueKind::BaseField,
                    1,
                )],
            )
            .unwrap(),
        ];
        let schedule =
            CompactResponseCheckpointSchedule::derive(&proof_geometry, &merkle_geometries).unwrap();
        assert_eq!(schedule.completed_proof_response_count(1), Ok(0));
        assert_eq!(schedule.completed_proof_response_count(2), Ok(2));

        let (public_geometry, public_bindings, public_bytes) = public_input();
        let decoded_public_input =
            decode_compact_public_input(public_geometry, public_bindings, &public_bytes).unwrap();
        let mut transcript =
            CompactProverTranscript::new(&proof_geometry, &decoded_public_input, &public_bytes)
                .unwrap();
        transcript
            .record_response_commitment(
                [0x71; Hash512::BYTE_LENGTH],
                [0x72; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH],
            )
            .unwrap();
        transcript.derive_verifier_message().unwrap();
        let assembler = CompactProofWireAssembler::new(&proof_geometry).unwrap();
        assert_eq!(
            assembler.canonical_prefix_bytes().len(),
            PROOF_FIXED_HEADER_BYTE_LENGTH
        );
        let boundary = compact_response_generation_checkpoint_boundary(
            &schedule,
            &transcript,
            &assembler,
            CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
        )
        .expect("header-only durable boundary");

        let restored_transcript = CompactProverTranscript::restore_from_checkpoint_cursor(
            &proof_geometry,
            &decoded_public_input,
            &public_bytes,
            boundary.canonical_transcript_cursor_bytes(),
            boundary
                .canonical_transcript_cursor_digest()
                .expect("checkpoint carries transcript cursor digest"),
        )
        .unwrap();
        let restored_assembler = CompactProofWireAssembler::restore_from_canonical_prefix(
            &proof_geometry,
            assembler.canonical_prefix_bytes(),
            0,
        )
        .unwrap();
        assert_eq!(
            compact_response_generation_checkpoint_boundary(
                &schedule,
                &restored_transcript,
                &restored_assembler,
                CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
            )
            .unwrap(),
            boundary
        );
    }

    #[test]
    fn checkpoint_boundary_refuses_wrong_progress_and_binds_every_prefix_byte() {
        let proof_geometry = proof_wire_geometry();
        let schedule = CompactResponseCheckpointSchedule::derive(
            &proof_geometry,
            &response_merkle_geometries(),
        )
        .expect("checkpoint schedule");
        let responses = response_inputs();
        let (public_geometry, public_bindings, public_bytes) = public_input();
        let decoded_public_input =
            decode_compact_public_input(public_geometry, public_bindings, &public_bytes)
                .expect("decoded public input");
        let mut transcript =
            CompactProverTranscript::new(&proof_geometry, &decoded_public_input, &public_bytes)
                .expect("prover transcript");
        for verifier_move_ordinal in 0..3 {
            record_response_and_derive_message(&mut transcript, verifier_move_ordinal);
        }

        let mut canonical_assembler = CompactProofWireAssembler::new(&proof_geometry).unwrap();
        canonical_assembler.append_response(&responses[0]).unwrap();
        let canonical_boundary = compact_response_generation_checkpoint_boundary(
            &schedule,
            &transcript,
            &canonical_assembler,
            CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
        )
        .expect("canonical checkpoint boundary");
        assert_eq!(
            compact_response_generation_checkpoint_boundary(
                &schedule,
                &transcript,
                &canonical_assembler,
                &[],
            ),
            Err(CompactGenerationCheckpointError::InvalidPrivateRandomnessCursor)
        );
        let oversized_private_randomness_cursor =
            vec![0x41; MAXIMUM_COMPACT_CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTE_LENGTH + 1];
        assert_eq!(
            compact_response_generation_checkpoint_boundary(
                &schedule,
                &transcript,
                &canonical_assembler,
                &oversized_private_randomness_cursor,
            ),
            Err(CompactGenerationCheckpointError::InvalidPrivateRandomnessCursor)
        );
        let changed_private_randomness_cursor_boundary =
            compact_response_generation_checkpoint_boundary(
                &schedule,
                &transcript,
                &canonical_assembler,
                b"changed compact construction private-randomness cursor",
            )
            .expect("changed private-randomness cursor remains canonical");
        assert_ne!(
            changed_private_randomness_cursor_boundary.committed_state_digest(),
            canonical_boundary.committed_state_digest(),
            "the exact compact construction private-randomness cursor must enter the committed checkpoint state"
        );

        let mut over_advanced_assembler = CompactProofWireAssembler::new(&proof_geometry).unwrap();
        over_advanced_assembler
            .append_response(&responses[0])
            .unwrap();
        over_advanced_assembler
            .append_response(&responses[1])
            .unwrap();
        assert_eq!(
            compact_response_generation_checkpoint_boundary(
                &schedule,
                &transcript,
                &over_advanced_assembler,
                CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
            ),
            Err(CompactGenerationCheckpointError::WrongResponseBoundary)
        );

        let substituted_root_response = response_input(0, 0x91, 11);
        let mut substituted_root_assembler =
            CompactProofWireAssembler::new(&proof_geometry).unwrap();
        substituted_root_assembler
            .append_response(&substituted_root_response)
            .unwrap();
        assert_eq!(
            compact_response_generation_checkpoint_boundary(
                &schedule,
                &transcript,
                &substituted_root_assembler,
                CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
            ),
            Err(CompactGenerationCheckpointError::Transcript(
                CompactTranscriptError::WrongCheckpointCursor
            ))
        );

        let changed_value_response = response_input(0, 0x11, 97);
        let mut changed_value_assembler = CompactProofWireAssembler::new(&proof_geometry).unwrap();
        changed_value_assembler
            .append_response(&changed_value_response)
            .unwrap();
        let changed_value_boundary = compact_response_generation_checkpoint_boundary(
            &schedule,
            &transcript,
            &changed_value_assembler,
            CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
        )
        .expect("root-and-salt-compatible changed response bytes");
        assert_ne!(
            changed_value_boundary.committed_state_digest(),
            canonical_boundary.committed_state_digest(),
            "response values must enter the committed checkpoint state"
        );

        record_response_and_derive_message(&mut transcript, 3);
        assert_eq!(
            compact_response_generation_checkpoint_boundary(
                &schedule,
                &transcript,
                &canonical_assembler,
                CONSTRUCTION_PRIVATE_RANDOMNESS_CURSOR_BYTES,
            ),
            Err(CompactGenerationCheckpointError::WrongResponseBoundary)
        );
    }
}
