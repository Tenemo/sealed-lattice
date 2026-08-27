use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    batched_hidden_bit_check_320::BatchedHiddenBitCheckCatalog320,
    preparation_kmac_call_census_320::{
        PreparationKmacCallCensus320, PreparationKmacCallCensusError320,
    },
    pseudorandom_zero_sharing_320::PerBitPseudorandomZeroSharingWorkload320,
};

#[test]
fn completion_per_bit_census_counts_every_current_emitted_kmac_call() {
    let circuit = completion_circuit();
    let workload = PerBitPseudorandomZeroSharingWorkload320::derive(&circuit).unwrap();
    let census = PreparationKmacCallCensus320::derive(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.participant_count,
        workload.zero_sharing_count,
    )
    .unwrap();

    assert_eq!(census.participant_count, 10);
    assert_eq!(census.masked_ballot_author_package_count, 10);
    assert_eq!(census.zero_sharing_count, 33_346);

    assert_eq!(census.seed_mailbox_key_derivation.semantic_call_count, 90);
    assert_eq!(
        census
            .seed_mailbox_key_derivation
            .successful_physical_call_count,
        180
    );
    assert_eq!(
        census.seed_mailbox_key_derivation.call,
        super::preparation_kmac_call_census_320::KmacCallShape320 {
            customization_byte_length: 51,
            key_byte_length: 32,
            message_byte_length: 1_655,
            right_encoded_output_length_byte_length: 3,
            output_byte_length: 32,
            absorb_block_count: 15,
            squeeze_block_count: 1,
            permutation_count: 15,
        }
    );
    assert_eq!(census.seed_mailbox_nonce_derivation.semantic_call_count, 90);
    assert_eq!(
        census.seed_mailbox_nonce_derivation.call,
        super::preparation_kmac_call_census_320::KmacCallShape320 {
            customization_byte_length: 53,
            key_byte_length: 32,
            message_byte_length: 208,
            right_encoded_output_length_byte_length: 2,
            output_byte_length: 12,
            absorb_block_count: 4,
            squeeze_block_count: 1,
            permutation_count: 4,
        }
    );

    assert_eq!(
        census
            .masked_ballot_mailbox_key_derivation
            .semantic_call_count,
        100
    );
    assert_eq!(
        census.masked_ballot_mailbox_key_derivation.call,
        super::preparation_kmac_call_census_320::KmacCallShape320 {
            customization_byte_length: 63,
            key_byte_length: 32,
            message_byte_length: 1_479,
            right_encoded_output_length_byte_length: 3,
            output_byte_length: 32,
            absorb_block_count: 13,
            squeeze_block_count: 1,
            permutation_count: 13,
        }
    );
    assert_eq!(
        census.masked_ballot_mailbox_nonce_derivation.call,
        super::preparation_kmac_call_census_320::KmacCallShape320 {
            customization_byte_length: 65,
            key_byte_length: 32,
            message_byte_length: 326,
            right_encoded_output_length_byte_length: 2,
            output_byte_length: 12,
            absorb_block_count: 5,
            squeeze_block_count: 1,
            permutation_count: 5,
        }
    );

    assert_eq!(census.full_field_stream_output.semantic_call_count, 360);
    assert_eq!(
        census
            .full_field_stream_output
            .successful_physical_call_count,
        2_520
    );
    assert_eq!(
        census.full_field_stream_output.call,
        super::preparation_kmac_call_census_320::KmacCallShape320 {
            customization_byte_length: 55,
            key_byte_length: 40,
            message_byte_length: 302,
            right_encoded_output_length_byte_length: 2,
            output_byte_length: 1_048_560,
            absorb_block_count: 5,
            squeeze_block_count: 7_710,
            permutation_count: 7_714,
        }
    );
    assert_eq!(census.final_field_stream_output.semantic_call_count, 360);
    assert_eq!(
        census.final_field_stream_output.call.output_byte_length,
        285_280
    );
    assert_eq!(
        census.final_field_stream_output.call.squeeze_block_count,
        2_098
    );
    assert_eq!(
        census.final_field_stream_output.call.permutation_count,
        2_102
    );

    assert_eq!(census.checkpoint_key_derivation.semantic_call_count, 10);
    assert_eq!(
        census.checkpoint_key_derivation.call,
        super::preparation_kmac_call_census_320::KmacCallShape320 {
            customization_byte_length: 70,
            key_byte_length: 40,
            message_byte_length: 3_908,
            right_encoded_output_length_byte_length: 3,
            output_byte_length: 40,
            absorb_block_count: 31,
            squeeze_block_count: 1,
            permutation_count: 31,
        }
    );
    assert_eq!(census.checkpoint_tag.semantic_call_count, 5_040);
    assert_eq!(
        census
            .checkpoint_tag
            .minimum_message_call
            .message_byte_length,
        285_561
    );
    assert_eq!(
        census
            .checkpoint_tag
            .maximum_message_call
            .message_byte_length,
        1_048_842
    );
    assert_eq!(
        census.checkpoint_tag.cumulative_message_byte_length,
        3_362_695_540
    );
    assert_eq!(
        census
            .checkpoint_tag
            .minimum_message_call
            .absorb_block_count,
        2_102
    );
    assert_eq!(
        census
            .checkpoint_tag
            .maximum_message_call
            .absorb_block_count,
        7_715
    );
    assert_eq!(census.semantic_call_count, 6_150);
    assert_eq!(census.successful_physical_call_count, 10_850);
    assert_eq!(census.additional_physical_call_count_per_cold_restore, 2);
}

#[test]
fn completion_batched_candidate_changes_only_the_source_and_checkpoint_families() {
    let circuit = completion_circuit();
    let context = TallyPreparationContext::new(
        Hash512::from_bytes([0x11; 64]),
        Hash512::from_bytes([0x12; 64]),
        [0x13; 32],
        &circuit,
    )
    .unwrap();
    let catalog =
        BatchedHiddenBitCheckCatalog320::derive(Hash512::from_bytes([0x14; 64]), context, &circuit)
            .unwrap();
    let census = PreparationKmacCallCensus320::derive(
        FOUNDATION_PROFILE.participant_count,
        FOUNDATION_PROFILE.participant_count,
        catalog.zero_sharing_count(),
    )
    .unwrap();

    assert_eq!(census.zero_sharing_count, 5_426);
    assert_eq!(census.full_field_stream_output.semantic_call_count, 0);
    assert_eq!(census.final_field_stream_output.semantic_call_count, 360);
    assert_eq!(
        census.final_field_stream_output.call.output_byte_length,
        217_040
    );
    assert_eq!(
        census.final_field_stream_output.call.squeeze_block_count,
        1_596
    );
    assert_eq!(
        census.final_field_stream_output.call.permutation_count,
        1_600
    );
    assert_eq!(census.checkpoint_tag.semantic_call_count, 2_520);
    assert_eq!(
        census
            .checkpoint_tag
            .minimum_message_call
            .message_byte_length,
        217_320
    );
    assert_eq!(
        census
            .checkpoint_tag
            .maximum_message_call
            .message_byte_length,
        217_321
    );
    assert_eq!(
        census.checkpoint_tag.cumulative_message_byte_length,
        547_647_650
    );
    assert_eq!(
        census.checkpoint_tag.minimum_message_call.permutation_count,
        1_600
    );
    assert_eq!(
        census.checkpoint_tag.maximum_message_call.permutation_count,
        1_600
    );
    assert_eq!(census.semantic_call_count, 3_270);
    assert_eq!(census.successful_physical_call_count, 5_810);
}

#[test]
fn roster_and_chunk_boundaries_preserve_subset_replication_multiplicities() {
    for participant_count in [4_u16, 7, 10, 13, 20] {
        let active_fault_bound = u64::from((participant_count - 1) / 3);
        let authorized_subset_count =
            binomial_coefficient(u64::from(participant_count), active_fault_bound);
        let authorized_subset_size = u64::from(participant_count) - active_fault_bound;
        let authorized_subset_count_per_participant =
            binomial_coefficient(u64::from(participant_count - 1), active_fault_bound);
        for zero_sharing_count in [1_u64, 26_214, 26_215] {
            let census = PreparationKmacCallCensus320::derive(
                participant_count,
                participant_count,
                zero_sharing_count,
            )
            .unwrap();
            let chunk_count = if zero_sharing_count <= 26_214 { 1 } else { 2 };
            let subset_basis_count = authorized_subset_count * active_fault_bound;
            let semantic_field_call_count = subset_basis_count * chunk_count;
            let physical_field_call_count = semantic_field_call_count * authorized_subset_size;
            let checkpoint_call_count = u64::from(participant_count)
                * authorized_subset_count_per_participant
                * active_fault_bound
                * chunk_count;

            assert_eq!(
                census.full_field_stream_output.semantic_call_count
                    + census.final_field_stream_output.semantic_call_count,
                semantic_field_call_count
            );
            assert_eq!(
                census
                    .full_field_stream_output
                    .successful_physical_call_count
                    + census
                        .final_field_stream_output
                        .successful_physical_call_count,
                physical_field_call_count
            );
            assert_eq!(
                census.checkpoint_tag.semantic_call_count,
                checkpoint_call_count
            );
            assert_eq!(
                census.seed_mailbox_key_derivation.semantic_call_count,
                u64::from(participant_count) * u64::from(participant_count - 1)
            );
            assert_eq!(
                census
                    .masked_ballot_mailbox_key_derivation
                    .semantic_call_count,
                u64::from(participant_count) * u64::from(participant_count)
            );
        }
    }

    let exact_full_chunk = PreparationKmacCallCensus320::derive(10, 0, 26_214).unwrap();
    assert_eq!(
        exact_full_chunk
            .final_field_stream_output
            .call
            .output_byte_length,
        1_048_560
    );
    let one_field_over = PreparationKmacCallCensus320::derive(10, 0, 26_215).unwrap();
    assert_eq!(
        one_field_over
            .final_field_stream_output
            .call
            .output_byte_length,
        40
    );
    assert_eq!(
        one_field_over
            .final_field_stream_output
            .call
            .permutation_count,
        5
    );
}

#[test]
fn invalid_counts_fail_before_a_census_is_returned() {
    assert_eq!(
        PreparationKmacCallCensus320::derive(10, 11, 1),
        Err(
            PreparationKmacCallCensusError320::MaskedBallotAuthorPackageCountOutOfRange {
                package_count: 11,
                participant_count: 10,
            }
        )
    );
    assert!(PreparationKmacCallCensus320::derive(3, 0, 1).is_err());
    assert!(PreparationKmacCallCensus320::derive(10, 0, 0).is_err());
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

fn binomial_coefficient(total: u64, selected: u64) -> u64 {
    let selected = selected.min(total - selected);
    (0..selected).fold(1_u64, |value, index| value * (total - index) / (index + 1))
}
