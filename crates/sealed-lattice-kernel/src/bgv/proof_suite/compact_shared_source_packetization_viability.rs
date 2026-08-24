//! Necessary geometry for an application-level compact packet redesign.
//!
//! This test-only owner compares two concrete hypotheses. A single global
//! lookup challenge commits every quotient before packet work begins. The
//! alternative keeps each packet's lookup self-contained and commits only the
//! production values that must agree across packets. Neither hypothesis is a
//! proof contract: the current implementation has no reusable shared-source
//! oracle, subset-equality reduction, compound transcript, or atomic packet
//! verifier. The counts below therefore cannot authorize proof generation.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    bgv::{
        key_switch_topology::KeySwitchDecompositionTopology,
        proof_suite::relation_plan::BallotValidityWitnessValueSource,
        setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
    },
    foundation::{FOUNDATION_PROFILE, ProofApplicationSlotCeilings},
};

use super::{
    compact_cfw_external::CompactCfwExternalStorageCatalog,
    compact_cfw_geometry::CompactCfwGeometry,
    compact_public_key_static_catalog::selected_initial_whir_codeword_byte_length,
    external_memory::{
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT,
        MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH,
    },
    relation_plan::{
        TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE,
        compile_galois_key_share_relation_with_source_layout,
        compile_relinearization_round_one_relation_with_source_layout,
        compile_relinearization_round_two_relation_with_source_layout,
    },
    selected_ballot_validity_relation_compilation, selected_evaluator_aggregate_relation_plan,
    selected_profile::{
        selected_galois_key_share_relation_plan_input, selected_relation_plan_check_context,
        selected_relinearization_relation_plan_inputs,
    },
};

const BASE_FIELD_ELEMENT_BYTE_LENGTH: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PacketSideGeometry {
    witness_ring_vector_count: u64,
    public_input_ring_vector_count: u64,
    padded_side_ring_vector_count: u64,
    external_peak_stored_byte_length: u64,
    external_total_written_byte_length: u64,
    external_total_read_byte_length: u64,
    external_object_lifecycle_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EvaluatorPacketFamilyGeometry {
    work_packets: Box<[PacketSideGeometry]>,
    range_packets: Box<[PacketSideGeometry]>,
    common_secret_anchor_packet: PacketSideGeometry,
    shared_source_ring_vector_count: u64,
}

impl EvaluatorPacketFamilyGeometry {
    fn packet_count(&self) -> usize {
        self.work_packets.len() + self.range_packets.len() + 1
    }

    fn full_reference_dimension_packet_count(&self) -> usize {
        self.work_packets
            .iter()
            .chain(self.range_packets.iter())
            .chain(core::iter::once(&self.common_secret_anchor_packet))
            .filter(|packet| packet.padded_side_ring_vector_count == 128)
            .count()
    }

    fn public_input_ring_vector_count(&self) -> u64 {
        self.work_packets
            .iter()
            .chain(self.range_packets.iter())
            .chain(core::iter::once(&self.common_secret_anchor_packet))
            .map(|packet| packet.public_input_ring_vector_count)
            .sum()
    }
}

fn direct_lookup_table_ring_vector_count(ring_degree: u64) -> Option<u64> {
    TRUSTEE_QUOTIENT_MAXIMUM_ABSOLUTE_VALUE
        .checked_mul(2)?
        .checked_add(1)?
        .checked_add(ring_degree.checked_sub(1)?)?
        .checked_div(ring_degree)
}

fn shared_anchor_quotient_ring_vector_count() -> Option<u64> {
    u64::try_from(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len())
        .ok()?
        .checked_mul(u64::try_from(SETUP_COMMITMENT_MODULE_RANK.checked_add(1)?).ok()?)
}

fn required_padded_side_ring_vector_count(
    ring_degree: u64,
    witness_ring_vector_count: u64,
    public_input_ring_vector_count: u64,
) -> Option<u64> {
    let witness_element_count = witness_ring_vector_count.checked_mul(ring_degree)?;
    let public_input_element_count = public_input_ring_vector_count
        .checked_mul(ring_degree)?
        .checked_add(1)?;
    let padded_element_count = witness_element_count
        .max(public_input_element_count)
        .checked_next_power_of_two()?;
    padded_element_count.checked_div(ring_degree)
}

fn derive_packet_side_geometry(
    ring_degree: u64,
    witness_ring_vector_count: u64,
    public_input_ring_vector_count: u64,
) -> Option<PacketSideGeometry> {
    let padded_side_ring_vector_count = required_padded_side_ring_vector_count(
        ring_degree,
        witness_ring_vector_count,
        public_input_ring_vector_count,
    )?;
    let padded_witness_element_count = padded_side_ring_vector_count.checked_mul(ring_degree)?;
    let cfw_geometry =
        CompactCfwGeometry::derive(usize::try_from(padded_witness_element_count).ok()?).ok()?;
    let storage = CompactCfwExternalStorageCatalog::derive(cfw_geometry).ok()?;
    Some(PacketSideGeometry {
        witness_ring_vector_count,
        public_input_ring_vector_count,
        padded_side_ring_vector_count,
        external_peak_stored_byte_length: storage.peak_stored_byte_length(),
        external_total_written_byte_length: storage.total_written_byte_length(),
        external_total_read_byte_length: storage.total_read_byte_length(),
        external_object_lifecycle_count: storage.object_lifecycle_count(),
    })
}

fn local_lookup_work_packet(
    ring_degree: u64,
    quotient_ring_vector_count: u64,
    shared_small_ring_vector_count: u64,
    public_input_ring_vector_count: u64,
) -> Option<PacketSideGeometry> {
    let witness_ring_vector_count = quotient_ring_vector_count
        .checked_mul(2)?
        .checked_add(direct_lookup_table_ring_vector_count(ring_degree)?)?
        .checked_add(shared_small_ring_vector_count)?;
    derive_packet_side_geometry(
        ring_degree,
        witness_ring_vector_count,
        public_input_ring_vector_count,
    )
}

fn small_range_packet(
    ring_degree: u64,
    shifted_ternary_ring_vector_count: u64,
    shifted_eta_two_ring_vector_count: u64,
    public_input_ring_vector_count: u64,
) -> Option<PacketSideGeometry> {
    let witness_ring_vector_count = shifted_ternary_ring_vector_count
        .checked_mul(2)?
        .checked_add(shifted_eta_two_ring_vector_count.checked_mul(4)?)?;
    derive_packet_side_geometry(
        ring_degree,
        witness_ring_vector_count,
        public_input_ring_vector_count,
    )
}

fn common_secret_anchor_packet(ring_degree: u64) -> Option<PacketSideGeometry> {
    let quotient_ring_vector_count = shared_anchor_quotient_ring_vector_count()?;
    let lookup_table_ring_vector_count = direct_lookup_table_ring_vector_count(ring_degree)?;
    let common_secret_copy_ring_vector_count = 1;
    let hiding_small_ring_vector_count = 9;
    let hiding_small_product_ring_vector_count = 9;
    let witness_ring_vector_count = quotient_ring_vector_count
        .checked_mul(2)?
        .checked_add(lookup_table_ring_vector_count)?
        .checked_add(common_secret_copy_ring_vector_count)?
        .checked_add(hiding_small_ring_vector_count)?
        .checked_add(hiding_small_product_ring_vector_count)?;
    let public_commitment_and_matrix_ring_vector_count = 15;
    derive_packet_side_geometry(
        ring_degree,
        witness_ring_vector_count,
        public_commitment_and_matrix_ring_vector_count,
    )
}

fn initial_whir_codeword_byte_length(
    ring_degree: u64,
    source_ring_vector_count: u64,
) -> Option<u64> {
    let padded_source_ring_vector_count = source_ring_vector_count.checked_next_power_of_two()?;
    let message_element_count = padded_source_ring_vector_count.checked_mul(ring_degree)?;
    selected_initial_whir_codeword_byte_length(message_element_count)
}

fn relation_context(schema_identifier: u16) -> super::RelationPlanCheckContext {
    selected_relation_plan_check_context(schema_identifier)
        .expect("the selected relation context derives")
}

fn derive_relinearization_round_one_packets() -> EvaluatorPacketFamilyGeometry {
    let (round_one_input, _) = selected_relinearization_relation_plan_inputs()
        .expect("the selected relinearization inputs derive");
    let compiled = compile_relinearization_round_one_relation_with_source_layout(
        &round_one_input,
        &relation_context(
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
        ),
    )
    .expect("the round-one production relation compiles");
    assert_eq!(
        compiled
            .semantic_modular_quotient_ring_vector_count()
            .expect("the round-one quotient count derives"),
        422
    );

    let ring_degree = round_one_input.geometry.ring_degree;
    let modulus_count_per_block = u64::try_from(
        round_one_input.geometry.data_moduli.len() + round_one_input.geometry.special_moduli.len(),
    )
    .expect("the selected modulus count fits u64");
    let block_count = round_one_input.geometry.decomposition_blocks.len();
    let work_packets = (0..block_count)
        .map(|_| {
            let quotient_count = 2 * modulus_count_per_block;
            local_lookup_work_packet(
                ring_degree,
                quotient_count,
                4,
                quotient_count + modulus_count_per_block,
            )
            .expect("one round-one block fits the local-lookup packet envelope")
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let range_packets = vec![
        small_range_packet(ring_degree, 2, 2 * u64::try_from(block_count).unwrap(), 0)
            .expect("the round-one shared range packet fits"),
    ]
    .into_boxed_slice();
    EvaluatorPacketFamilyGeometry {
        work_packets,
        range_packets,
        common_secret_anchor_packet: common_secret_anchor_packet(ring_degree)
            .expect("the common-secret anchor packet fits"),
        shared_source_ring_vector_count: 2 + 2 * u64::try_from(block_count).unwrap(),
    }
}

fn derive_relinearization_round_two_packets() -> EvaluatorPacketFamilyGeometry {
    let (_, round_two_input) = selected_relinearization_relation_plan_inputs()
        .expect("the selected relinearization inputs derive");
    let compiled = compile_relinearization_round_two_relation_with_source_layout(
        &round_two_input,
        &relation_context(
            ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
        ),
    )
    .expect("the round-two production relation compiles");
    assert_eq!(
        compiled
            .semantic_modular_quotient_ring_vector_count()
            .expect("the round-two quotient count derives"),
        630
    );

    let ring_degree = round_two_input.geometry.ring_degree;
    let modulus_count_per_block = u64::try_from(
        round_two_input.geometry.data_moduli.len() + round_two_input.geometry.special_moduli.len(),
    )
    .expect("the selected modulus count fits u64");
    let block_count = round_two_input.geometry.decomposition_blocks.len();
    let mut work_packets = Vec::with_capacity(block_count * 2);
    for _ in 0..block_count {
        let quotient_count = 2 * modulus_count_per_block;
        work_packets.push(
            local_lookup_work_packet(
                ring_degree,
                quotient_count,
                4,
                quotient_count + modulus_count_per_block,
            )
            .expect("one repeated round-one block fits"),
        );
    }
    for _ in 0..block_count {
        let quotient_count = modulus_count_per_block;
        work_packets.push(
            local_lookup_work_packet(ring_degree, quotient_count, 3, 3 * quotient_count)
                .expect("one round-two block fits"),
        );
    }
    let range_packets = vec![
        small_range_packet(ring_degree, 2, 3 * u64::try_from(block_count).unwrap(), 0)
            .expect("the round-two shared range packet fits"),
    ]
    .into_boxed_slice();
    EvaluatorPacketFamilyGeometry {
        work_packets: work_packets.into_boxed_slice(),
        range_packets,
        common_secret_anchor_packet: common_secret_anchor_packet(ring_degree)
            .expect("the common-secret anchor packet fits"),
        shared_source_ring_vector_count: 2 + 3 * u64::try_from(block_count).unwrap(),
    }
}

fn derive_galois_packets() -> EvaluatorPacketFamilyGeometry {
    let input =
        selected_galois_key_share_relation_plan_input().expect("the selected Galois input derives");
    let compiled = compile_galois_key_share_relation_with_source_layout(
        &input,
        &relation_context(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        ),
    )
    .expect("the Galois production relation compiles");
    assert_eq!(
        compiled
            .semantic_modular_quotient_ring_vector_count()
            .expect("the Galois quotient count derives"),
        738
    );

    let ring_degree = input.geometry.ring_degree;
    let mut work_packets = Vec::new();
    let mut total_error_ring_vector_count = 0_u64;
    for entry in &input.ordered_entries {
        let topology = KeySwitchDecompositionTopology::for_level(entry.selected_level)
            .expect("the selected Galois level has a key-switch topology");
        let modulus_count_per_block =
            u64::try_from(topology.extended_moduli().len()).expect("the modulus count fits u64");
        let block_count = topology.data_block_count();
        total_error_ring_vector_count += u64::try_from(block_count).unwrap();
        let maximum_blocks_per_packet = if modulus_count_per_block == 18 { 3 } else { 2 };
        let mut remaining_block_count = block_count;
        while remaining_block_count != 0 {
            let packet_block_count = remaining_block_count.min(maximum_blocks_per_packet);
            let packet_block_count_u64 = u64::try_from(packet_block_count).unwrap();
            let quotient_count = packet_block_count_u64 * modulus_count_per_block;
            work_packets.push(
                local_lookup_work_packet(
                    ring_degree,
                    quotient_count,
                    2 + packet_block_count_u64,
                    2 * quotient_count,
                )
                .expect("the deterministic Galois block group fits"),
            );
            remaining_block_count -= packet_block_count;
        }
    }
    let range_packets = vec![
        small_range_packet(ring_degree, 7, 28, 6)
            .expect("the first Galois range and automorphism packet fits"),
        small_range_packet(ring_degree, 0, total_error_ring_vector_count - 28, 0)
            .expect("the remaining Galois error range packet fits"),
    ]
    .into_boxed_slice();
    EvaluatorPacketFamilyGeometry {
        work_packets: work_packets.into_boxed_slice(),
        range_packets,
        common_secret_anchor_packet: common_secret_anchor_packet(ring_degree)
            .expect("the common-secret anchor packet fits"),
        shared_source_ring_vector_count: 7 + total_error_ring_vector_count,
    }
}

#[test]
fn one_global_lookup_commitment_already_reaches_the_common_scratch_ceiling() {
    let input =
        selected_galois_key_share_relation_plan_input().expect("the selected Galois input derives");
    let compiled = compile_galois_key_share_relation_with_source_layout(
        &input,
        &relation_context(
            ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
        ),
    )
    .expect("the Galois production relation compiles");
    let quotient_count = compiled
        .semantic_modular_quotient_ring_vector_count()
        .expect("the quotient count derives");
    let shared_small_source_count = 43;
    let lookup_table_count = direct_lookup_table_ring_vector_count(input.geometry.ring_degree)
        .expect("the quotient lookup table derives");
    let committed_source_ring_vector_count = quotient_count
        .checked_add(shared_small_source_count)
        .and_then(|count| count.checked_add(lookup_table_count))
        .expect("the global source count fits");
    assert_eq!(committed_source_ring_vector_count, 791);
    assert_eq!(
        committed_source_ring_vector_count.next_power_of_two(),
        1_024
    );
    let initial_codeword_byte_length = initial_whir_codeword_byte_length(
        input.geometry.ring_degree,
        committed_source_ring_vector_count,
    )
    .expect("the initial WHIR codeword byte length derives");
    assert_eq!(initial_codeword_byte_length, 1_073_741_824);
    assert!(
        initial_codeword_byte_length >= MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
    );
}

#[test]
fn local_lookup_packets_fit_individually_but_multiply_full_dimension_work() {
    let round_one = derive_relinearization_round_one_packets();
    let round_two = derive_relinearization_round_two_packets();
    let galois = derive_galois_packets();
    assert_eq!(
        (
            round_one.packet_count(),
            round_two.packet_count(),
            galois.packet_count(),
        ),
        (10, 18, 21)
    );
    assert_eq!(
        (
            round_one.full_reference_dimension_packet_count(),
            round_two.full_reference_dimension_packet_count(),
            galois.full_reference_dimension_packet_count(),
        ),
        (9, 17, 16)
    );
    assert_eq!(
        (
            round_one.shared_source_ring_vector_count,
            round_two.shared_source_ring_vector_count,
            galois.shared_source_ring_vector_count,
        ),
        (18, 26, 43)
    );
    assert_eq!(
        (
            round_one.public_input_ring_vector_count(),
            round_two.public_input_ring_vector_count(),
            galois.public_input_ring_vector_count(),
        ),
        (639, 1_263, 1_485)
    );

    let evaluator_packets = [&round_one, &round_two, &galois]
        .into_iter()
        .flat_map(|family| {
            family
                .work_packets
                .iter()
                .chain(family.range_packets.iter())
                .chain(core::iter::once(&family.common_secret_anchor_packet))
        })
        .collect::<Vec<_>>();
    assert_eq!(evaluator_packets.len(), 49);
    assert!(evaluator_packets.iter().all(|packet| {
        packet.external_peak_stored_byte_length
            < MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
            && usize::try_from(packet.external_object_lifecycle_count)
                .is_ok_and(|count| count < MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
    }));

    let full_dimension_packets = evaluator_packets
        .iter()
        .copied()
        .filter(|packet| packet.padded_side_ring_vector_count == 128)
        .collect::<Vec<_>>();
    assert_eq!(full_dimension_packets.len(), 42);
    let full_dimension_written_byte_length = full_dimension_packets
        .iter()
        .map(|packet| packet.external_total_written_byte_length)
        .sum::<u64>();
    let full_dimension_read_byte_length = full_dimension_packets
        .iter()
        .map(|packet| packet.external_total_read_byte_length)
        .sum::<u64>();
    assert_eq!(full_dimension_written_byte_length, 42_278_579_280);
    assert_eq!(full_dimension_read_byte_length, 84_557_148_480);

    let evaluator_public_input_payload_byte_length = [
        round_one.public_input_ring_vector_count(),
        round_two.public_input_ring_vector_count(),
        galois.public_input_ring_vector_count(),
    ]
    .into_iter()
    .sum::<u64>()
    .checked_mul(32_768)
    .and_then(|count| count.checked_mul(BASE_FIELD_ELEMENT_BYTE_LENGTH))
    .expect("the evaluator public-input payload length fits");
    assert_eq!(evaluator_public_input_payload_byte_length, 887_881_728);

    println!("family,packet-count,full-128-packets,shared-source-vectors,public-input-vectors");
    for (name, family) in [
        ("relinearization-round-one", &round_one),
        ("relinearization-round-two", &round_two),
        ("galois-key-share", &galois),
    ] {
        println!(
            "{name},{},{},{},{}",
            family.packet_count(),
            family.full_reference_dimension_packet_count(),
            family.shared_source_ring_vector_count,
            family.public_input_ring_vector_count(),
        );
    }
    println!(
        "evaluator-total,packets={},full-128-packets={},written-bytes={},read-bytes={},public-input-payload-bytes={}",
        evaluator_packets.len(),
        full_dimension_packets.len(),
        full_dimension_written_byte_length,
        full_dimension_read_byte_length,
        evaluator_public_input_payload_byte_length,
    );
    println!(
        "setup-per-participant-with-reference-public-key,packet-count={},full-128-packet-count={}",
        evaluator_packets.len() + 1,
        full_dimension_packets.len() + 1,
    );
    println!(
        "setup-ceremony-with-reference-public-key,packet-count={},full-128-packet-count={}",
        (evaluator_packets.len() + 1) * usize::from(FOUNDATION_PROFILE.participant_count),
        (full_dimension_packets.len() + 1) * usize::from(FOUNDATION_PROFILE.participant_count),
    );
}

#[test]
fn bounding_set_owners_remain_uncompiled_for_the_packet_contract() {
    let ballot = selected_ballot_validity_relation_compilation()
        .expect("the selected ballot relation compiles");
    let ballot_variant = ballot
        .relation_plan()
        .select_variant(None, None)
        .expect("the selected ballot variant exists");
    let unique_ballot_sources = (0..u32::try_from(ballot_variant.ordered_columns().len()).unwrap())
        .filter_map(|column_ordinal| ballot.source_plan().recipe(column_ordinal))
        .map(|recipe| recipe.value_source())
        .collect::<BTreeSet<_>>();
    let ballot_source_counts = unique_ballot_sources.iter().fold(
        BTreeMap::<&'static str, u64>::new(),
        |mut counts, source| {
            let name = match source {
                BallotValidityWitnessValueSource::ScoreIndicator { .. } => "score-indicator",
                BallotValidityWitnessValueSource::PairCharacterAuxiliaryCoefficient { .. } => {
                    "pair-character-auxiliary"
                }
                BallotValidityWitnessValueSource::ReversedRandomizerShifted { .. } => {
                    "reversed-randomizer"
                }
                BallotValidityWitnessValueSource::ErrorShifted { .. } => "encryption-error",
                BallotValidityWitnessValueSource::EncoderReduction { .. } => "encoder-reduction",
                BallotValidityWitnessValueSource::PairCharacterProductQuotient { .. } => {
                    "pair-character-product-quotient"
                }
                BallotValidityWitnessValueSource::EncryptionQuotient { .. } => {
                    "encryption-quotient"
                }
            };
            *counts.entry(name).or_default() += 1;
            counts
        },
    );

    let aggregate_plan = selected_evaluator_aggregate_relation_plan()
        .expect("the evaluator-key aggregate relation derives");
    let aggregate_variant = aggregate_plan
        .variants()
        .iter()
        .max_by_key(|variant| {
            variant
                .ordered_columns()
                .iter()
                .filter(|column| {
                    matches!(
                        column.origin(),
                        super::relation_plan::RelationColumnOrigin::VerifierSequence { .. }
                            | super::relation_plan::RelationColumnOrigin::BoundTree { .. }
                    )
                })
                .count()
        })
        .expect("the aggregate relation has a production variant");
    let aggregate_origin_counts =
        aggregate_variant
            .ordered_columns()
            .iter()
            .fold([0_u64; 3], |mut counts, column| {
                use super::relation_plan::RelationColumnOrigin;
                match column.origin() {
                    RelationColumnOrigin::VerifierSequence { .. } => counts[0] += 1,
                    RelationColumnOrigin::BoundTree { .. } => counts[1] += 1,
                    RelationColumnOrigin::Prover => counts[2] += 1,
                }
                counts
            });
    assert_eq!(aggregate_origin_counts, [0, 20_680, 0]);
    assert_eq!(aggregate_variant.ordered_constraint_count(), 1_880);

    println!("ballot-unique-production-sources,{ballot_source_counts:?}");
    println!(
        "ballot-source-column-recipes,{}",
        (0..u32::try_from(ballot_variant.ordered_columns().len()).unwrap())
            .filter(|column_ordinal| ballot.source_plan().recipe(*column_ordinal).is_some())
            .count()
    );
    println!(
        "aggregate-column-origins,verifier={},bound={},prover={},constraints={}",
        aggregate_origin_counts[0],
        aggregate_origin_counts[1],
        aggregate_origin_counts[2],
        aggregate_variant.ordered_constraint_count(),
    );
}
