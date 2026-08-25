use crate::{
    foundation::FOUNDATION_PROFILE,
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile},
};

use super::replicated_random_bit_resource_model::ReplicatedRandomBitResourceModel;

const REPLICATED_RANDOM_BIT_STREAM_DOMAIN: &str =
    "sealed-lattice/tally-preparation/replicated-random-bit-stream/v1";
const REPLICATED_KEY_COORDINATE_MAGIC: &str = "sealed-lattice/replicated-key-coordinate";
const REPLICATED_RANDOM_BIT_CATALOG_MAGIC: &str = "sealed-lattice/replicated-random-bit-catalog";
const REPLICATED_RANDOM_BIT_CATALOG_IDENTITY_DOMAIN: &str =
    "sealed-lattice/replicated-random-bit-catalog-identity/v1";
const HASH512_PREIMAGE_PREFIX: &str = "sealed.vote/hash512";

#[test]
fn completion_resource_model_matches_exact_production_geometry() {
    let model = ReplicatedRandomBitResourceModel::derive(&completion_circuit()).unwrap();
    assert_eq!(
        model,
        ReplicatedRandomBitResourceModel {
            participant_count: 10,
            unique_random_sharing_key_count: 120,
            key_stream_count_per_participant: 84,
            total_local_key_stream_count: 840,
            chunk_count_per_key_stream: 1,
            chunked_xof_invocation_count_per_participant: 84,
            total_chunked_xof_invocation_count: 840,
            semantic_mask_bit_count_per_key: 6_652,
            additive_correlation_free_point_bit_count_per_key: 1_951_920,
            component_bit_count_per_key: 1_958_572,
            unique_component_bit_count: 235_028_640,
            component_bit_count_per_participant: 164_520_048,
            total_locally_generated_component_bit_count: 1_645_200_480,
            emitted_byte_length_per_key: 244_822,
            unique_emitted_byte_length: 29_378_640,
            emitted_byte_length_per_participant: 20_565_048,
            total_locally_emitted_byte_length: 205_650_480,
            unused_high_bit_count_per_key: 4,
            catalog_canonical_byte_length: 13_305,
            catalog_identity_preimage_byte_length: 13_384,
            catalog_identity_fixed_keccak_f1600_permutation_count_per_participant: 99,
            total_catalog_identity_fixed_keccak_f1600_permutation_count: 990,
            minimum_absorbed_query_byte_length_per_participant: 38_353,
            maximum_absorbed_query_byte_length_per_participant: 38_368,
            total_absorbed_query_byte_length: 383_635,
            minimum_fixed_keccak_f1600_permutation_count_per_participant: 151_536,
            maximum_fixed_keccak_f1600_permutation_count_per_participant: 151_536,
            total_fixed_keccak_f1600_permutation_count: 1_515_360,
            minimum_combined_fixed_keccak_f1600_permutation_count_per_participant: 151_635,
            maximum_combined_fixed_keccak_f1600_permutation_count_per_participant: 151_635,
            total_combined_fixed_keccak_f1600_permutation_count: 1_516_350,
            maximum_single_query_byte_length: 457,
            maximum_single_output_byte_length: 244_822,
            maximum_fixed_keccak_f1600_permutation_count_per_chunk: 1_804,
            maximum_chunk_boundary_recomputation_byte_length: 244_822,
        }
    );
}

#[test]
fn independent_completion_derivation_matches_production_resource_model() {
    let circuit = completion_circuit();
    let production = ReplicatedRandomBitResourceModel::derive(&circuit).unwrap();
    let independent = independently_derive_completion_resource_model(&circuit);

    assert_eq!(
        independent.unique_key_count,
        production.unique_random_sharing_key_count
    );
    assert_eq!(
        independent.key_count_per_participant,
        production.key_stream_count_per_participant
    );
    assert_eq!(
        independent.minimum_query_bytes_per_participant,
        production.minimum_absorbed_query_byte_length_per_participant
    );
    assert_eq!(
        independent.maximum_query_bytes_per_participant,
        production.maximum_absorbed_query_byte_length_per_participant
    );
    assert_eq!(
        independent.total_query_bytes,
        production.total_absorbed_query_byte_length
    );
    assert_eq!(
        independent.catalog_canonical_byte_length,
        production.catalog_canonical_byte_length
    );
    assert_eq!(
        independent.catalog_identity_preimage_byte_length,
        production.catalog_identity_preimage_byte_length
    );
    assert_eq!(
        independent.catalog_identity_permutation_count,
        production.catalog_identity_fixed_keccak_f1600_permutation_count_per_participant
    );
    assert_eq!(
        independent.permutations_per_participant,
        production.minimum_fixed_keccak_f1600_permutation_count_per_participant
    );
    assert_eq!(
        production.minimum_fixed_keccak_f1600_permutation_count_per_participant,
        production.maximum_fixed_keccak_f1600_permutation_count_per_participant
    );
}

#[test]
fn maximum_shape_resource_model_preserves_chunk_and_output_totals() {
    let circuit =
        CompiledTallyCircuit::compile(TallyCircuitProfile::new(20, 20, 20).unwrap()).unwrap();
    let model = ReplicatedRandomBitResourceModel::derive(&circuit).unwrap();
    assert!(model.chunk_count_per_key_stream > 1);
    assert_eq!(
        model.chunked_xof_invocation_count_per_participant,
        model.key_stream_count_per_participant * model.chunk_count_per_key_stream
    );
    assert_eq!(
        model.emitted_byte_length_per_participant,
        model.key_stream_count_per_participant * model.emitted_byte_length_per_key
    );
    assert!(model.maximum_single_output_byte_length <= 1_048_576);
    assert_eq!(
        model.maximum_chunk_boundary_recomputation_byte_length,
        model.maximum_single_output_byte_length
    );
}

#[derive(Debug, Clone, Copy)]
struct IndependentCompletionResourceModel {
    unique_key_count: u64,
    key_count_per_participant: u64,
    minimum_query_bytes_per_participant: u64,
    maximum_query_bytes_per_participant: u64,
    total_query_bytes: u64,
    permutations_per_participant: u64,
    catalog_canonical_byte_length: u64,
    catalog_identity_preimage_byte_length: u64,
    catalog_identity_permutation_count: u64,
}

fn independently_derive_completion_resource_model(
    circuit: &CompiledTallyCircuit,
) -> IndependentCompletionResourceModel {
    let participant_count = 10_u64;
    let active_fault_bound = 3_u64;
    let component_bit_count_per_key = 1_958_572_u64;
    let output_byte_length_per_key = independent_ceiling_divide(component_bit_count_per_key, 8);
    let output_rate_block_count = independent_ceiling_divide(output_byte_length_per_key, 136);
    let mut unique_key_count = 0_u64;
    let mut query_bytes_by_participant = vec![0_u64; participant_count as usize];
    let mut key_count_by_participant = vec![0_u64; participant_count as usize];
    let mut complete_absorbed_blocks_by_participant = vec![0_u64; participant_count as usize];

    for excluded_mask in 0_u64..(1_u64 << participant_count) {
        if u64::from(excluded_mask.count_ones()) != active_fault_bound {
            continue;
        }
        unique_key_count += 1;
        let coordinate_byte_length =
            independent_coordinate_byte_length(participant_count, excluded_mask);
        let query_byte_length = independent_query_byte_length(coordinate_byte_length);
        for participant_position in 0..participant_count {
            if excluded_mask & (1_u64 << participant_position) != 0 {
                continue;
            }
            let participant_index = participant_position as usize;
            query_bytes_by_participant[participant_index] += query_byte_length;
            key_count_by_participant[participant_index] += 1;
            complete_absorbed_blocks_by_participant[participant_index] += query_byte_length / 136;
        }
    }

    let key_count_per_participant = uniform(&key_count_by_participant);
    let complete_absorbed_blocks_per_participant =
        uniform(&complete_absorbed_blocks_by_participant);
    let semantic_mask_wire_indices = (0..circuit.geometry().input_bit_count)
        .chain(circuit.operations().iter().enumerate().filter_map(
            |(operation_position, operation)| {
                matches!(operation, BooleanOperation::Conjunction { .. })
                    .then_some(circuit.geometry().input_bit_count + operation_position)
            },
        ))
        .map(|wire_index| u64::try_from(wire_index).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(semantic_mask_wire_indices.len(), 6_652);
    let catalog_canonical_byte_length =
        framed_length(u64::try_from(REPLICATED_RANDOM_BIT_CATALOG_MAGIC.len()).unwrap())
            + varuint_length(1)
            + framed_length(64)
            + varuint_length(participant_count)
            + varuint_length(u64::try_from(circuit.geometry().input_bit_count).unwrap())
            + varuint_length(1)
            + varuint_length(u64::try_from(semantic_mask_wire_indices.len()).unwrap())
            + semantic_mask_wire_indices
                .iter()
                .copied()
                .map(varuint_length)
                .sum::<u64>()
            + varuint_length(2)
            + varuint_length(u64::try_from(circuit.geometry().conjunction_gate_count).unwrap())
            + varuint_length(4)
            + varuint_length(participant_count)
            + varuint_length(participant_count - 1)
            + varuint_length(1_951_920)
            + varuint_length(component_bit_count_per_key);
    let catalog_identity_preimage_byte_length = u64::try_from(HASH512_PREIMAGE_PREFIX.len())
        .unwrap()
        + framed_length(
            u64::try_from(REPLICATED_RANDOM_BIT_CATALOG_IDENTITY_DOMAIN.len()).unwrap(),
        )
        + varuint_length(1)
        + framed_length(catalog_canonical_byte_length);
    let catalog_identity_permutation_count =
        catalog_identity_preimage_byte_length / 136 + independent_ceiling_divide(64, 136);
    IndependentCompletionResourceModel {
        unique_key_count,
        key_count_per_participant,
        minimum_query_bytes_per_participant: *query_bytes_by_participant.iter().min().unwrap(),
        maximum_query_bytes_per_participant: *query_bytes_by_participant.iter().max().unwrap(),
        total_query_bytes: query_bytes_by_participant.iter().sum(),
        permutations_per_participant: complete_absorbed_blocks_per_participant
            + key_count_per_participant * output_rate_block_count,
        catalog_canonical_byte_length,
        catalog_identity_preimage_byte_length,
        catalog_identity_permutation_count,
    }
}

fn independent_coordinate_byte_length(participant_count: u64, excluded_mask: u64) -> u64 {
    framed_length(REPLICATED_KEY_COORDINATE_MAGIC.len() as u64)
        + varuint_length(1)
        + framed_length(64)
        + varuint_length(participant_count)
        + varuint_length(excluded_mask)
        + varuint_length(1)
}

fn independent_query_byte_length(coordinate_byte_length: u64) -> u64 {
    let tuple_header_byte_length = 8_u64;
    let item_count = 13_u64;
    let item_header_byte_length = 6_u64;
    let domain_payload_byte_length = 4 + REPLICATED_RANDOM_BIT_STREAM_DOMAIN.len() as u64;
    let key_payload_byte_length = 64_u64;
    let coordinate_payload_byte_length = 4 + coordinate_byte_length;
    let catalog_identity_payload_byte_length = 64_u64;
    let unsigned16_payload_byte_length = 2 * 2_u64;
    let unsigned64_payload_byte_length = 7 * 8_u64;
    tuple_header_byte_length
        + item_count * item_header_byte_length
        + domain_payload_byte_length
        + key_payload_byte_length
        + coordinate_payload_byte_length
        + catalog_identity_payload_byte_length
        + unsigned16_payload_byte_length
        + unsigned64_payload_byte_length
}

fn framed_length(byte_length: u64) -> u64 {
    varuint_length(byte_length) + byte_length
}

fn varuint_length(mut value: u64) -> u64 {
    let mut byte_length = 1_u64;
    while value >= 128 {
        value >>= 7;
        byte_length += 1;
    }
    byte_length
}

fn independent_ceiling_divide(dividend: u64, divisor: u64) -> u64 {
    dividend / divisor + u64::from(!dividend.is_multiple_of(divisor))
}

fn uniform(values: &[u64]) -> u64 {
    let first = values[0];
    assert!(values.iter().all(|value| *value == first));
    first
}

fn completion_circuit() -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap()
}
