//! Independent assignment of decoded verifier-message coordinates.
//!
//! The canonical contract generator consumes these ranges to assign every
//! sampled extension element, base-field element, and distinct-query group to
//! the verifier role that uses it. Canonical proof/public-input decoding,
//! transcript hashing, and Merkle verification remain owned by their runtime
//! modules rather than being restated here.

use std::ops::Range;

use super::CompactStaticCatalogError;
use super::cfw_reduction::CfwReductionCatalog;
use super::transcript_chronology::{
    PackingTranscriptChronology, TranscriptEpoch, VerifierMoveRole,
};
use super::uniform_verifier_randomness::PackingUniformVerifierRandomness;
use crate::bgv::proof_suite::fixed_uniform_verifier_message::FixedUniformVerifierMessageGeometry;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DecodedChallengeConsumer {
    pub(super) role: VerifierMoveRole,
    pub(super) extension_output_range: Range<u64>,
    pub(super) base_field_output_range: Range<u64>,
    pub(super) distinct_query_group_range: Range<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DecodedChallengeConsumers {
    by_move: Vec<Vec<DecodedChallengeConsumer>>,
}

impl DecodedChallengeConsumers {
    pub(super) fn derive(
        chronology: &PackingTranscriptChronology,
        uniform_verifier_randomness: &PackingUniformVerifierRandomness,
        cfw_reduction: &CfwReductionCatalog,
    ) -> Result<Self, CompactStaticCatalogError> {
        if chronology.verifier_moves().len() != uniform_verifier_randomness.move_count() {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        let by_move = chronology
            .verifier_moves()
            .iter()
            .enumerate()
            .map(|(move_index, verifier_move)| {
                let geometry = uniform_verifier_randomness.fixed_message_geometry(move_index)?;
                let consumers =
                    derive_move_consumers(verifier_move.roles(), &geometry, cfw_reduction)?;
                check_exact_partition(&geometry, &consumers)?;
                Ok(consumers)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { by_move })
    }

    pub(super) fn for_move(&self, move_index: usize) -> Option<&[DecodedChallengeConsumer]> {
        self.by_move.get(move_index).map(Vec::as_slice)
    }
}

fn derive_move_consumers(
    roles: &[VerifierMoveRole],
    geometry: &FixedUniformVerifierMessageGeometry,
    cfw_reduction: &CfwReductionCatalog,
) -> Result<Vec<DecodedChallengeConsumer>, CompactStaticCatalogError> {
    let extension_count = geometry.extension_output_count();
    let base_count = geometry.base_field_output_count();
    let group_count = u64::try_from(geometry.distinct_query_groups().len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    match roles {
        [role] => Ok(vec![DecodedChallengeConsumer {
            role: *role,
            extension_output_range: 0..extension_count,
            base_field_output_range: 0..base_count,
            distinct_query_group_range: 0..group_count,
        }]),
        [
            VerifierMoveRole::CfwJointConstraint,
            opening_role @ VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::PreChallenge,
            },
        ] => {
            let joint_count = u64::from(cfw_reduction.joint_constraint_randomness_element_count());
            if extension_count != checked_add(joint_count, 1)?
                || base_count != 0
                || group_count != 0
            {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            Ok(vec![
                DecodedChallengeConsumer {
                    role: VerifierMoveRole::CfwJointConstraint,
                    extension_output_range: 0..joint_count,
                    base_field_output_range: 0..0,
                    distinct_query_group_range: 0..0,
                },
                DecodedChallengeConsumer {
                    role: *opening_role,
                    extension_output_range: joint_count..extension_count,
                    base_field_output_range: 0..0,
                    distinct_query_group_range: 0..0,
                },
            ])
        }
        [
            final_query_role @ VerifierMoveRole::WhirFinalQueries {
                epoch: TranscriptEpoch::PreChallenge,
            },
            opening_role @ VerifierMoveRole::WhirOpeningBatching {
                epoch: TranscriptEpoch::Main,
            },
        ] => {
            if extension_count != 1 || base_count != 0 || group_count == 0 {
                return Err(CompactStaticCatalogError::InvalidGeometry);
            }
            Ok(vec![
                DecodedChallengeConsumer {
                    role: *final_query_role,
                    extension_output_range: 0..0,
                    base_field_output_range: 0..0,
                    distinct_query_group_range: 0..group_count,
                },
                DecodedChallengeConsumer {
                    role: *opening_role,
                    extension_output_range: 0..1,
                    base_field_output_range: 0..0,
                    distinct_query_group_range: 0..0,
                },
            ])
        }
        _ => Err(CompactStaticCatalogError::InvalidGeometry),
    }
}

fn check_exact_partition(
    geometry: &FixedUniformVerifierMessageGeometry,
    consumers: &[DecodedChallengeConsumer],
) -> Result<(), CompactStaticCatalogError> {
    let group_count = u64::try_from(geometry.distinct_query_groups().len())
        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?;
    check_ranges(
        geometry.extension_output_count(),
        consumers
            .iter()
            .map(|consumer| &consumer.extension_output_range),
    )?;
    check_ranges(
        geometry.base_field_output_count(),
        consumers
            .iter()
            .map(|consumer| &consumer.base_field_output_range),
    )?;
    check_ranges(
        group_count,
        consumers
            .iter()
            .map(|consumer| &consumer.distinct_query_group_range),
    )
}

fn check_ranges<'range>(
    element_count: u64,
    ranges: impl Iterator<Item = &'range Range<u64>>,
) -> Result<(), CompactStaticCatalogError> {
    let mut coverage = vec![
        0_u8;
        usize::try_from(element_count)
            .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?
    ];
    for range in ranges {
        if range.start > range.end || range.end > element_count {
            return Err(CompactStaticCatalogError::InvalidGeometry);
        }
        for ordinal in range.clone() {
            let count = coverage
                .get_mut(
                    usize::try_from(ordinal)
                        .map_err(|_| CompactStaticCatalogError::ArithmeticOverflow)?,
                )
                .ok_or(CompactStaticCatalogError::InvalidGeometry)?;
            *count = count
                .checked_add(1)
                .ok_or(CompactStaticCatalogError::ArithmeticOverflow)?;
        }
    }
    if coverage.iter().any(|count| *count != 1) {
        return Err(CompactStaticCatalogError::InvalidGeometry);
    }
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, CompactStaticCatalogError> {
    left.checked_add(right)
        .ok_or(CompactStaticCatalogError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use crate::bgv::proof_suite::compact_proof_wire::{
        COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH, CompactProofResponseWireGeometry,
        CompactProofResponseWireInput, CompactProofWireError, CompactProofWireGeometry,
        CompactProofWireInput, CompactPublicInputBindings, CompactPublicInputWireGeometry,
        decode_compact_proof_wire, decode_compact_public_input, encode_compact_proof_wire,
        encode_compact_public_input,
    };
    use crate::bgv::proof_suite::compact_public_key_static_catalog::{
        BASE_FIELD_ELEMENT_BYTE_LENGTH, CompactPublicKeyStaticCatalog,
        PRIVATE_LEAF_SALT_BYTE_LENGTH,
    };
    use crate::bgv::proof_suite::compact_response_merkle::{
        CompactResponseComponentGeometry, CompactResponseLeafValue, CompactResponseLeafValueKind,
        CompactResponseMerkleError, CompactResponseMerkleGeometry, CompactResponseQuerySchedule,
        CompactResponseQuerySelection, compact_response_leaf_digest,
        compact_response_merkle_parent_digest, verify_decoded_compact_response_opening,
        verify_decoded_compact_response_opening_with_leaf_ordinals_for_test,
    };
    use crate::bgv::proof_suite::compact_transcript::{
        CompactProverTranscript, derive_compact_fiat_shamir_verifier_message,
    };
    use crate::bgv::proof_suite::field::ProofBaseFieldElement;
    use crate::bgv::proof_suite::fixed_uniform_verifier_message::{
        DecodedFixedUniformVerifierMessage, FixedUniformDistinctQueryGeometry,
        FixedUniformVerifierMessageGeometry,
    };
    use crate::bgv::proof_suite::merkle::{
        maximum_minimal_frontier_node_count, minimal_frontier_coordinates,
    };
    use crate::foundation::Hash512;

    type Digest = [u8; Hash512::BYTE_LENGTH];
    type LeafSalt = [u8; PRIVATE_LEAF_SALT_BYTE_LENGTH as usize];

    struct SmallTransportedOpening {
        proof_geometry: CompactProofWireGeometry,
        merkle_geometry: CompactResponseMerkleGeometry,
        public_input_geometry: CompactPublicInputWireGeometry,
        public_input_bindings: CompactPublicInputBindings,
        canonical_public_input_bytes: Vec<u8>,
        canonical_proof_bytes: Vec<u8>,
        prover_verifier_message: DecodedFixedUniformVerifierMessage,
        query_leaf_ordinals: Vec<u64>,
    }

    fn base(value: u64) -> ProofBaseFieldElement {
        ProofBaseFieldElement::from_canonical(value).expect("small canonical base-field value")
    }

    fn build_tree(
        geometry: &CompactResponseMerkleGeometry,
        leaf_values: &[ProofBaseFieldElement],
        leaf_salts: &[LeafSalt],
    ) -> Vec<Vec<Digest>> {
        let leaves = leaf_values
            .iter()
            .zip(leaf_salts)
            .enumerate()
            .map(|(leaf_ordinal, (value, salt))| {
                compact_response_leaf_digest(
                    geometry,
                    u64::try_from(leaf_ordinal).expect("small leaf ordinal"),
                    CompactResponseLeafValue::BaseField(std::slice::from_ref(value)),
                    salt,
                )
                .expect("small canonical response leaf")
            })
            .collect::<Vec<_>>();
        let mut levels = vec![leaves];
        while levels.last().expect("tree level").len() > 1 {
            let parent_level = u32::try_from(levels.len()).expect("small parent level");
            let parents = levels
                .last()
                .expect("tree level")
                .chunks_exact(2)
                .enumerate()
                .map(|(parent_ordinal, children)| {
                    compact_response_merkle_parent_digest(
                        geometry,
                        parent_level,
                        u64::try_from(parent_ordinal * 2).expect("small child ordinal"),
                        children[0],
                        children[1],
                    )
                    .expect("small canonical response parent")
                })
                .collect();
            levels.push(parents);
        }
        levels
    }

    fn small_transported_opening() -> SmallTransportedOpening {
        let verifier_message_geometry = FixedUniformVerifierMessageGeometry::new(
            0,
            0,
            0,
            vec![FixedUniformDistinctQueryGeometry::new(8, 3)],
        )
        .expect("small verifier-message geometry");
        let merkle_geometry = CompactResponseMerkleGeometry::new(
            0,
            vec![CompactResponseComponentGeometry::new(
                0,
                8,
                3,
                CompactResponseQuerySelection::VerifierMessageDistinctGroup {
                    logical_verifier_move_ordinal: 0,
                    distinct_query_group_ordinal: 0,
                },
                CompactResponseLeafValueKind::BaseField,
                1,
            )],
        )
        .expect("small response Merkle geometry");
        let maximum_frontier_node_count = u64::try_from(
            maximum_minimal_frontier_node_count(8, 3).expect("small frontier ceiling"),
        )
        .expect("small frontier ceiling fits u64");
        let proof_geometry = CompactProofWireGeometry::new(vec![
            CompactProofResponseWireGeometry::new(
                0,
                3,
                0,
                3,
                maximum_frontier_node_count,
                verifier_message_geometry,
            )
            .expect("small response wire geometry"),
        ])
        .expect("small proof wire geometry");
        CompactResponseQuerySchedule::validate_registry(
            std::slice::from_ref(&merkle_geometry),
            proof_geometry.responses(),
        )
        .expect("small query registry");

        let public_input_geometry =
            CompactPublicInputWireGeometry::new(1, 2).expect("small public-input geometry");
        let public_input_bindings = CompactPublicInputBindings::new(
            Hash512::from_bytes([0x11; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x22; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x33; Hash512::BYTE_LENGTH]),
            Hash512::from_bytes([0x44; Hash512::BYTE_LENGTH]),
        );
        let canonical_public_input_bytes = encode_compact_public_input(
            public_input_geometry,
            public_input_bindings,
            &[base(3), base(5)],
        )
        .expect("small canonical public input");
        let decoded_public_input = decode_compact_public_input(
            public_input_geometry,
            public_input_bindings,
            &canonical_public_input_bytes,
        )
        .expect("small decoded public input");

        let leaf_values = (0_u64..8)
            .map(|ordinal| base(11 + ordinal))
            .collect::<Vec<_>>();
        let leaf_salts = (0_u8..8)
            .map(|ordinal| [ordinal + 1; PRIVATE_LEAF_SALT_BYTE_LENGTH as usize])
            .collect::<Vec<_>>();
        let tree = build_tree(&merkle_geometry, &leaf_values, &leaf_salts);
        let root = tree.last().expect("root level")[0];
        let round_salt = [0x5a; COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH];
        let mut transcript = CompactProverTranscript::new(
            &proof_geometry,
            &decoded_public_input,
            &canonical_public_input_bytes,
        )
        .expect("small prover transcript");
        transcript
            .record_response_commitment(root, round_salt)
            .expect("small response commitment");
        let prover_verifier_message = transcript
            .derive_verifier_message()
            .expect("live verifier message");
        transcript.finish().expect("complete small transcript");
        let query_schedule = CompactResponseQuerySchedule::derive(
            &merkle_geometry,
            proof_geometry.responses(),
            std::slice::from_ref(&prover_verifier_message),
        )
        .expect("live transcript-derived query schedule");
        let query_leaf_ordinals = query_schedule.as_slice().to_vec();
        let opened_values = query_leaf_ordinals
            .iter()
            .map(|ordinal| leaf_values[usize::try_from(*ordinal).expect("small query ordinal")])
            .collect();
        let opened_salts = query_leaf_ordinals
            .iter()
            .map(|ordinal| leaf_salts[usize::try_from(*ordinal).expect("small query ordinal")])
            .collect();
        let frontier = minimal_frontier_coordinates(&query_leaf_ordinals, leaf_values.len())
            .expect("small minimal frontier")
            .into_iter()
            .map(|(level, node_ordinal)| {
                tree[usize::try_from(level).expect("small level")]
                    [usize::try_from(node_ordinal).expect("small node ordinal")]
            })
            .collect();
        let canonical_proof_bytes = encode_compact_proof_wire(
            &proof_geometry,
            &CompactProofWireInput::new(vec![CompactProofResponseWireInput::new(
                root,
                round_salt,
                opened_values,
                Vec::new(),
                opened_salts,
                frontier,
            )]),
        )
        .expect("small canonical proof");

        SmallTransportedOpening {
            proof_geometry,
            merkle_geometry,
            public_input_geometry,
            public_input_bindings,
            canonical_public_input_bytes,
            canonical_proof_bytes,
            prover_verifier_message,
            query_leaf_ordinals,
        }
    }

    fn verify_transport(
        fixture: &SmallTransportedOpening,
        proof_bytes: &[u8],
    ) -> Result<Vec<u64>, CompactResponseMerkleError> {
        let public_input = decode_compact_public_input(
            fixture.public_input_geometry,
            fixture.public_input_bindings,
            &fixture.canonical_public_input_bytes,
        )
        .expect("fresh transported public input");
        let proof = decode_compact_proof_wire(&fixture.proof_geometry, proof_bytes)
            .expect("canonical transported proof");
        let verifier_message = derive_compact_fiat_shamir_verifier_message(
            &fixture.proof_geometry,
            &proof,
            proof_bytes,
            &public_input,
            &fixture.canonical_public_input_bytes,
            0,
        )
        .expect("verifier message from transported bytes");
        let query_schedule = CompactResponseQuerySchedule::derive(
            &fixture.merkle_geometry,
            fixture.proof_geometry.responses(),
            std::slice::from_ref(&verifier_message),
        )
        .expect("query schedule from transported bytes");
        verify_decoded_compact_response_opening(
            &fixture.merkle_geometry,
            &fixture.proof_geometry.responses()[0],
            &proof.responses()[0],
            proof_bytes,
            &query_schedule,
        )?;
        Ok(query_schedule.as_slice().to_vec())
    }

    #[test]
    fn factor_one_assigns_every_decoded_challenge_once() {
        let catalog = CompactPublicKeyStaticCatalog::derive()
            .expect("compact public-key static packing ledger");
        let selected = &catalog.selected;
        assert_eq!(
            selected.decoded_challenge_consumers.by_move.len(),
            selected.transcript_chronology.verifier_moves().len()
        );
        for (move_index, verifier_move) in selected
            .transcript_chronology
            .verifier_moves()
            .iter()
            .enumerate()
        {
            let consumers = selected
                .decoded_challenge_consumers
                .for_move(move_index)
                .expect("decoded challenge consumers");
            assert_eq!(
                consumers
                    .iter()
                    .map(|consumer| consumer.role)
                    .collect::<Vec<_>>(),
                verifier_move.roles()
            );
        }
    }

    #[test]
    fn transported_bytes_drive_fresh_transcript_and_merkle_verification() {
        let fixture = small_transported_opening();
        assert_eq!(
            verify_transport(&fixture, &fixture.canonical_proof_bytes),
            Ok(fixture.query_leaf_ordinals.clone())
        );
        let public_input = decode_compact_public_input(
            fixture.public_input_geometry,
            fixture.public_input_bindings,
            &fixture.canonical_public_input_bytes,
        )
        .expect("fresh transported public input");
        let proof =
            decode_compact_proof_wire(&fixture.proof_geometry, &fixture.canonical_proof_bytes)
                .expect("fresh transported proof");
        assert_eq!(
            derive_compact_fiat_shamir_verifier_message(
                &fixture.proof_geometry,
                &proof,
                &fixture.canonical_proof_bytes,
                &public_input,
                &fixture.canonical_public_input_bytes,
                0,
            ),
            Ok(fixture.prover_verifier_message)
        );
    }

    #[test]
    fn transported_load_bearing_regions_refuse_mutation() {
        let fixture = small_transported_opening();
        let response_start =
            crate::bgv::proof_suite::compact_proof_wire::PROOF_FIXED_HEADER_BYTE_LENGTH;
        let root_start = response_start + std::mem::size_of::<u32>();
        let round_salt_start = root_start + Hash512::BYTE_LENGTH;
        let base_values_start = round_salt_start + COMPACT_FIAT_SHAMIR_ROUND_SALT_BYTE_LENGTH;
        let leaf_salts_start = base_values_start + 3 * BASE_FIELD_ELEMENT_BYTE_LENGTH as usize;
        let frontier_start = leaf_salts_start
            + 3 * PRIVATE_LEAF_SALT_BYTE_LENGTH as usize
            + 2 * std::mem::size_of::<u32>();

        for offset in [
            root_start,
            round_salt_start,
            base_values_start,
            leaf_salts_start,
        ] {
            let mut mutated = fixture.canonical_proof_bytes.clone();
            mutated[offset] ^= 1;
            assert!(matches!(
                verify_transport(&fixture, &mutated),
                Err(CompactResponseMerkleError::RootMismatch
                    | CompactResponseMerkleError::WrongFrontierLength)
            ));
        }

        let mut frontier_mutation = fixture.canonical_proof_bytes.clone();
        frontier_mutation[frontier_start] ^= 1;
        match decode_compact_proof_wire(&fixture.proof_geometry, &frontier_mutation) {
            Ok(proof) => assert_eq!(
                verify_decoded_compact_response_opening_with_leaf_ordinals_for_test(
                    &fixture.merkle_geometry,
                    &fixture.proof_geometry.responses()[0],
                    &proof.responses()[0],
                    &frontier_mutation,
                    &fixture.query_leaf_ordinals,
                ),
                Err(CompactResponseMerkleError::RootMismatch)
            ),
            Err(CompactProofWireError::DuplicateOrUnsortedFrontierDictionary) => {}
            Err(error) => panic!("unexpected frontier mutation refusal: {error:?}"),
        }
    }
}
