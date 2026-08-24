//! Optimistic costs for the current independent-packet evaluator-key lowering.
//!
//! This test-only owner deliberately omits anchors, small-secret ranges,
//! shared-witness equality openings, public inputs, proof bytes, and every
//! non-evaluator proof family. It therefore cannot authorize a packet
//! contract or a prover run. The result is a lower bound only for a design in
//! which every packet independently proves its quotient lookups with the
//! current lookup lowering. A shared lookup argument, a batched relation, or a
//! different witness representation would be a new construction and may have
//! different costs.

use std::collections::BTreeMap;

use crate::{
    bgv::setup::{SETUP_COMMITMENT_MODULE_RANK, SETUP_COMMITMENT_MODULUS_LIMB_INDICES},
    foundation::{FOUNDATION_PROFILE, ProofApplicationSlotCeilings},
};

use super::{
    ProofExternalMemoryError,
    compact_cfw_external::{CompactCfwExternalPlanError, CompactCfwExternalStorageCatalog},
    compact_cfw_geometry::CompactCfwGeometry,
    compact_proof_contract::selected_compact_public_key_proof_contract,
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
    selected_profile::{
        selected_galois_key_share_relation_plan_input, selected_relation_plan_check_context,
        selected_relinearization_relation_plan_inputs,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct QuotientPacketGeometry {
    quotient_ring_vector_count: u64,
    actual_witness_ring_vector_count: u64,
    padded_witness_ring_vector_count: u64,
    external_peak_stored_byte_length: u64,
    external_total_written_byte_length: u64,
    external_total_read_byte_length: u64,
    external_object_lifecycle_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndependentLookupPacketizationFloor {
    semantic_trustee_quotient_ring_vector_count: u64,
    ordered_packets: Vec<QuotientPacketGeometry>,
    external_total_written_byte_length: u64,
    external_total_read_byte_length: u64,
}

#[derive(Clone)]
struct PartialPacketization {
    total_padded_witness_ring_vector_count: u64,
    ordered_packets: Vec<QuotientPacketGeometry>,
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

fn storage_catalog_for_padded_ring_vector_count(
    ring_degree: u64,
    padded_witness_ring_vector_count: u64,
) -> Option<CompactCfwExternalStorageCatalog> {
    let padded_witness_element_count = ring_degree.checked_mul(padded_witness_ring_vector_count)?;
    let geometry =
        CompactCfwGeometry::derive(usize::try_from(padded_witness_element_count).ok()?).ok()?;
    CompactCfwExternalStorageCatalog::derive(geometry).ok()
}

fn derive_packet_geometry(
    ring_degree: u64,
    lookup_multiplicity_ring_vector_count: u64,
    quotient_ring_vector_count: u64,
) -> Option<QuotientPacketGeometry> {
    if quotient_ring_vector_count == 0 {
        return None;
    }
    let actual_witness_ring_vector_count = quotient_ring_vector_count
        .checked_mul(2)?
        .checked_add(lookup_multiplicity_ring_vector_count)?;
    let padded_witness_ring_vector_count = actual_witness_ring_vector_count.next_power_of_two();
    let storage = storage_catalog_for_padded_ring_vector_count(
        ring_degree,
        padded_witness_ring_vector_count,
    )?;
    Some(QuotientPacketGeometry {
        quotient_ring_vector_count,
        actual_witness_ring_vector_count,
        padded_witness_ring_vector_count,
        external_peak_stored_byte_length: storage.peak_stored_byte_length(),
        external_total_written_byte_length: storage.total_written_byte_length(),
        external_total_read_byte_length: storage.total_read_byte_length(),
        external_object_lifecycle_count: storage.object_lifecycle_count(),
    })
}

fn packetization_is_better(
    candidate: &PartialPacketization,
    current: &PartialPacketization,
) -> bool {
    (
        candidate.total_padded_witness_ring_vector_count,
        candidate.ordered_packets.len(),
    ) < (
        current.total_padded_witness_ring_vector_count,
        current.ordered_packets.len(),
    )
}

fn derive_independent_lookup_packetization_floor(
    ring_degree: u64,
    semantic_trustee_quotient_ring_vector_count: u64,
) -> Option<IndependentLookupPacketizationFloor> {
    let lookup_multiplicity_ring_vector_count = direct_lookup_table_ring_vector_count(ring_degree)?;
    let candidate_packets = (1..=semantic_trustee_quotient_ring_vector_count)
        .filter_map(|quotient_ring_vector_count| {
            derive_packet_geometry(
                ring_degree,
                lookup_multiplicity_ring_vector_count,
                quotient_ring_vector_count,
            )
        })
        .collect::<Vec<_>>();
    if candidate_packets.is_empty() {
        return None;
    }

    let quotient_count = usize::try_from(semantic_trustee_quotient_ring_vector_count).ok()?;
    let mut best_by_covered_quotient_count = vec![None; quotient_count.checked_add(1)?];
    best_by_covered_quotient_count[0] = Some(PartialPacketization {
        total_padded_witness_ring_vector_count: 0,
        ordered_packets: Vec::new(),
    });
    for covered_quotient_count in 0..quotient_count {
        let Some(partial) = best_by_covered_quotient_count[covered_quotient_count].clone() else {
            continue;
        };
        for packet in &candidate_packets {
            let next_covered_quotient_count = covered_quotient_count
                .checked_add(usize::try_from(packet.quotient_ring_vector_count).ok()?)?;
            if next_covered_quotient_count > quotient_count {
                continue;
            }
            let mut candidate = partial.clone();
            candidate.total_padded_witness_ring_vector_count = candidate
                .total_padded_witness_ring_vector_count
                .checked_add(packet.padded_witness_ring_vector_count)?;
            candidate.ordered_packets.push(*packet);
            match &best_by_covered_quotient_count[next_covered_quotient_count] {
                Some(current) if !packetization_is_better(&candidate, current) => {}
                _ => best_by_covered_quotient_count[next_covered_quotient_count] = Some(candidate),
            }
        }
    }
    let mut selected = best_by_covered_quotient_count.pop()??;
    selected.ordered_packets.sort_unstable_by_key(|packet| {
        (
            core::cmp::Reverse(packet.padded_witness_ring_vector_count),
            core::cmp::Reverse(packet.quotient_ring_vector_count),
        )
    });
    let external_total_written_byte_length = selected
        .ordered_packets
        .iter()
        .try_fold(0_u64, |total, packet| {
            total.checked_add(packet.external_total_written_byte_length)
        })?;
    let external_total_read_byte_length = selected
        .ordered_packets
        .iter()
        .try_fold(0_u64, |total, packet| {
            total.checked_add(packet.external_total_read_byte_length)
        })?;
    Some(IndependentLookupPacketizationFloor {
        semantic_trustee_quotient_ring_vector_count,
        ordered_packets: selected.ordered_packets,
        external_total_written_byte_length,
        external_total_read_byte_length,
    })
}

fn packet_dimension_counts(
    packetization: &IndependentLookupPacketizationFloor,
) -> BTreeMap<u64, u64> {
    packetization
        .ordered_packets
        .iter()
        .fold(BTreeMap::new(), |mut counts, packet| {
            *counts
                .entry(packet.padded_witness_ring_vector_count)
                .or_default() += 1;
            counts
        })
}

#[test]
fn independent_compact_lookup_packets_have_a_large_evaluator_key_floor() {
    let (round_one_input, round_two_input) = selected_relinearization_relation_plan_inputs()
        .expect("the selected relinearization relation inputs derive");
    let round_one_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_ONE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected round-one context derives");
    let round_two_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::RELINEARIZATION_ROUND_TWO_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected round-two context derives");
    let round_one = compile_relinearization_round_one_relation_with_source_layout(
        &round_one_input,
        &round_one_context,
    )
    .expect("the selected round-one relation compiles");
    let round_two = compile_relinearization_round_two_relation_with_source_layout(
        &round_two_input,
        &round_two_context,
    )
    .expect("the selected round-two relation compiles");

    let galois_input = selected_galois_key_share_relation_plan_input()
        .expect("the selected Galois relation input derives");
    let galois_context = selected_relation_plan_check_context(
        ProofApplicationSlotCeilings::GALOIS_KEY_SHARE_STATEMENT_SCHEMA_IDENTIFIER,
    )
    .expect("the selected Galois context derives");
    let galois =
        compile_galois_key_share_relation_with_source_layout(&galois_input, &galois_context)
            .expect("the selected Galois relation compiles");

    let ring_degree = round_one_input.geometry.ring_degree;
    assert_eq!(round_two_input.geometry.ring_degree, ring_degree);
    assert_eq!(galois_input.geometry.ring_degree, ring_degree);
    let shared_anchor_quotient_count =
        shared_anchor_quotient_ring_vector_count().expect("the shared anchor count derives");
    let semantic_trustee_quotient_counts = [
        round_one
            .semantic_modular_quotient_ring_vector_count()
            .expect("the round-one quotient count derives")
            .checked_sub(shared_anchor_quotient_count)
            .expect("round one contains the shared anchors"),
        round_two
            .semantic_modular_quotient_ring_vector_count()
            .expect("the round-two quotient count derives")
            .checked_sub(shared_anchor_quotient_count)
            .expect("round two contains the shared anchors"),
        galois
            .semantic_modular_quotient_ring_vector_count()
            .expect("the Galois quotient count derives")
            .checked_sub(shared_anchor_quotient_count)
            .expect("Galois sharing contains the shared anchors"),
    ];
    assert_eq!(semantic_trustee_quotient_counts, [416, 624, 732]);
    assert_eq!(direct_lookup_table_ring_vector_count(ring_degree), Some(10));

    let packetizations = semantic_trustee_quotient_counts.map(|quotient_count| {
        derive_independent_lookup_packetization_floor(ring_degree, quotient_count)
            .expect("the independent lookup packet floor derives")
    });
    assert_eq!(
        packet_dimension_counts(&packetizations[0]),
        [(16, 1), (128, 7)].into()
    );
    assert_eq!(
        packet_dimension_counts(&packetizations[1]),
        [(32, 1), (64, 1), (128, 10)].into()
    );
    assert_eq!(
        packet_dimension_counts(&packetizations[2]),
        [(64, 1), (128, 12)].into()
    );
    assert_eq!(
        packetizations
            .iter()
            .map(|packetization| packetization.ordered_packets.len())
            .collect::<Vec<_>>(),
        [8, 12, 13]
    );

    for packetization in &packetizations {
        assert!(packetization.ordered_packets.iter().all(|packet| {
            packet.external_peak_stored_byte_length
                < MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_STORED_BYTE_LENGTH
                && usize::try_from(packet.external_object_lifecycle_count)
                    .is_ok_and(|count| count < MAXIMUM_COMMON_PROOF_EXTERNAL_MEMORY_OBJECT_COUNT)
        }));
    }

    let reference_contract = selected_compact_public_key_proof_contract()
        .expect("the selected compact public-key contract derives");
    let reference_relation = reference_contract.verifier_inputs().relation;
    let reference_padded_ring_vector_count = reference_relation
        .padded_witness_element_count()
        .checked_div(ring_degree)
        .expect("the reference padded vector count derives");
    let reference_storage = storage_catalog_for_padded_ring_vector_count(
        ring_degree,
        reference_padded_ring_vector_count,
    )
    .expect("the reference storage geometry remains admitted");
    assert_eq!(reference_padded_ring_vector_count, 128);

    let evaluator_packet_count_per_participant = packetizations
        .iter()
        .try_fold(0_u64, |count, packetization| {
            count.checked_add(u64::try_from(packetization.ordered_packets.len()).ok()?)
        })
        .expect("the evaluator packet count fits");
    let setup_packet_count_per_participant = evaluator_packet_count_per_participant + 1;
    let full_reference_dimension_packet_count_per_participant = packetizations
        .iter()
        .flat_map(|packetization| &packetization.ordered_packets)
        .filter(|packet| {
            packet.padded_witness_ring_vector_count == reference_padded_ring_vector_count
        })
        .count()
        .checked_add(1)
        .and_then(|count| u64::try_from(count).ok())
        .expect("the full-dimension packet count fits");
    assert_eq!(setup_packet_count_per_participant, 34);
    assert_eq!(full_reference_dimension_packet_count_per_participant, 30);

    let quotient_only_written_byte_length = packetizations
        .iter()
        .try_fold(
            reference_storage.total_written_byte_length(),
            |total, packetization| {
                total.checked_add(packetization.external_total_written_byte_length)
            },
        )
        .expect("the optimistic written-byte lower bound fits");
    let quotient_only_read_byte_length = packetizations
        .iter()
        .try_fold(
            reference_storage.total_read_byte_length(),
            |total, packetization| total.checked_add(packetization.external_total_read_byte_length),
        )
        .expect("the optimistic read-byte lower bound fits");
    assert_eq!(quotient_only_written_byte_length, 31_583_105_040);
    assert_eq!(quotient_only_read_byte_length, 63_166_201_920);

    let participant_count = u64::from(FOUNDATION_PROFILE.participant_count);
    assert_eq!(participant_count, 10);
    assert_eq!(galois_input.ordered_entries.len(), 6);
    println!(
        "ring-degree,trustee-quotients,packet-count,padded-vector-counts,written-byte-lower-bound,read-byte-lower-bound"
    );
    for packetization in &packetizations {
        println!(
            "{},{},{},{:?},{},{}",
            ring_degree,
            packetization.semantic_trustee_quotient_ring_vector_count,
            packetization.ordered_packets.len(),
            packet_dimension_counts(packetization),
            packetization.external_total_written_byte_length,
            packetization.external_total_read_byte_length,
        );
    }
    println!(
        "per-participant-optimistic-setup-floor,packets={setup_packet_count_per_participant},full-reference-dimension-packets={full_reference_dimension_packet_count_per_participant},written-bytes={quotient_only_written_byte_length},read-bytes={quotient_only_read_byte_length}"
    );
    println!(
        "ceremony-optimistic-full-reference-dimension-packet-floor,{}",
        full_reference_dimension_packet_count_per_participant * participant_count
    );
}

#[test]
fn one_more_quotient_crosses_the_current_packet_storage_limit() {
    let ring_degree = 32_768;
    let lookup_multiplicity_ring_vector_count =
        direct_lookup_table_ring_vector_count(ring_degree).expect("the lookup table derives");
    let maximum_admitted =
        derive_packet_geometry(ring_degree, lookup_multiplicity_ring_vector_count, 59)
            .expect("59 quotient vectors fit the current packet envelope");
    assert_eq!(maximum_admitted.actual_witness_ring_vector_count, 128);
    assert_eq!(maximum_admitted.padded_witness_ring_vector_count, 128);

    let one_over_actual_witness_ring_vector_count = 60_u64
        .checked_mul(2)
        .and_then(|count| count.checked_add(lookup_multiplicity_ring_vector_count))
        .expect("the one-over witness count fits");
    assert_eq!(one_over_actual_witness_ring_vector_count, 130);
    let one_over_padded_witness_element_count = one_over_actual_witness_ring_vector_count
        .next_power_of_two()
        .checked_mul(ring_degree)
        .expect("the one-over padded element count fits");
    let one_over_geometry = CompactCfwGeometry::derive(
        usize::try_from(one_over_padded_witness_element_count)
            .expect("the one-over padded element count fits usize"),
    )
    .expect("the one-over CFW geometry derives");
    assert_eq!(
        CompactCfwExternalStorageCatalog::derive(one_over_geometry).unwrap_err(),
        CompactCfwExternalPlanError::ExternalMemory(
            ProofExternalMemoryError::ResourceLimitExceeded
        )
    );
}
