use crate::{
    foundation::{
        DECLARED_ADVERSARIAL_QUERY_BUDGET, FOUNDATION_PROFILE, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{TallyPreparationError, adaptive_oracle_repair::AdaptiveOracleRepairCensus};

#[test]
fn completion_profile_reproduces_the_adaptive_oracle_census() {
    let circuit = completion_profile_circuit();
    let census = AdaptiveOracleRepairCensus::derive(&circuit).unwrap();

    assert_eq!(
        census,
        AdaptiveOracleRepairCensus {
            participant_count: 10,
            active_fault_bound: 3,
            honest_holder_count: 7,
            implemented_share_reconstruction_threshold: 4,
            implemented_share_privacy_fault_bound: 3,
            roster_fault_bound_within_implemented_share_privacy: true,
            implemented_share_threshold_matches_roster: true,
            input_bit_count: 1_230,
            input_bit_count_per_participant: 123,
            fresh_label_wire_count: 6_652,
            conjunction_gate_count: 5_422,
            output_mask_count: 41,
            modeled_label_commitment_call_count: 133_040,
            modeled_authenticated_share_commitment_call_count: 475_590,
            modeled_garbling_generation_call_count: 216_880,
            modeled_garbling_evaluation_call_count: 54_220,
            modeled_core_shared_oracle_call_count: 879_730,
            modeled_core_shared_oracle_output_bit_count: 2_049_369_560,
            initial_hidden_label_commitment_point_count: 13_304,
            initial_hidden_garbling_point_count: 21_688,
            initial_hidden_label_share_commitment_point_count: 17_220,
            initial_hidden_scalar_share_commitment_point_count: 160_713,
            initial_hidden_point_count: 212_925,
            activation_patched_label_commitment_point_count: 6_652,
            activation_patched_garbling_point_count: 5_422,
            activation_patched_label_share_commitment_point_count: 8_610,
            activation_patched_active_row_commitment_point_count: 37_954,
            activation_patched_output_mask_commitment_point_count: 287,
            maximum_activation_patched_input_mask_commitment_point_count: 8_610,
            minimum_remaining_hidden_point_count: 145_390,
            maximum_remaining_hidden_point_count: 154_000,
            minimum_hidden_point_entropy_bit_count: 640,
            authenticated_share_salt_entropy_bit_count: 768,
            adaptive_reprogramming_stage_count: 1,
            declared_adversarial_query_budget: DECLARED_ADVERSARIAL_QUERY_BUDGET,
            conditional_advantage_numerator: 4 * DECLARED_ADVERSARIAL_QUERY_BUDGET,
            conditional_advantage_denominator_power: 320,
            conditional_strict_power_of_two_bound_exponent: 238,
        }
    );
}

#[test]
fn omitted_submissions_patch_only_their_input_mask_commitments() {
    let census = AdaptiveOracleRepairCensus::derive(&completion_profile_circuit()).unwrap();

    assert_eq!(census.remaining_hidden_point_count(10).unwrap(), 154_000);
    assert_eq!(census.remaining_hidden_point_count(9).unwrap(), 153_139);
    assert_eq!(census.remaining_hidden_point_count(5).unwrap(), 149_695);
    assert_eq!(census.remaining_hidden_point_count(0).unwrap(), 145_390);
    assert_eq!(
        census.remaining_hidden_point_count(11),
        Err(TallyPreparationError::SubmittedParticipantCountOutOfRange {
            submitted_participant_count: 11,
            participant_count: 10,
        })
    );
}

#[test]
fn every_admitted_shape_uses_roster_formulas_and_monotone_activation_counts() {
    for participant_count in
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT..=MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT
    {
        let roster_parameters = derive_foundation_roster_parameters(participant_count).unwrap();
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let census = AdaptiveOracleRepairCensus::derive(&circuit).unwrap();
                let honest_holder_count =
                    u64::from(participant_count - roster_parameters.active_fault_bound);

                assert_eq!(census.honest_holder_count, honest_holder_count);
                assert_eq!(
                    census.roster_fault_bound_within_implemented_share_privacy,
                    participant_count >= 4 && roster_parameters.active_fault_bound <= 3
                );
                assert_eq!(
                    census.implemented_share_threshold_matches_roster,
                    participant_count >= 4 && roster_parameters.reconstruction_threshold == 4
                );
                assert_eq!(
                    census.input_bit_count_per_participant * u64::from(participant_count),
                    census.input_bit_count
                );
                assert_eq!(
                    census.initial_hidden_label_commitment_point_count,
                    census.fresh_label_wire_count * 2
                );
                assert_eq!(
                    census.initial_hidden_garbling_point_count,
                    census.conjunction_gate_count * 4
                );
                assert_eq!(
                    census.activation_patched_active_row_commitment_point_count,
                    census.conjunction_gate_count * honest_holder_count
                );
                assert_eq!(
                    census.remaining_hidden_point_count(0).unwrap(),
                    census.minimum_remaining_hidden_point_count
                );
                assert_eq!(
                    census
                        .remaining_hidden_point_count(participant_count)
                        .unwrap(),
                    census.maximum_remaining_hidden_point_count
                );

                let mut previous_remaining_hidden_point_count =
                    census.remaining_hidden_point_count(0).unwrap();
                for submitted_participant_count in 1..=participant_count {
                    let remaining_hidden_point_count = census
                        .remaining_hidden_point_count(submitted_participant_count)
                        .unwrap();
                    assert_eq!(
                        remaining_hidden_point_count - previous_remaining_hidden_point_count,
                        census.input_bit_count_per_participant * honest_holder_count
                    );
                    previous_remaining_hidden_point_count = remaining_hidden_point_count;
                }
            }
        }
    }
}

fn completion_profile_circuit() -> CompiledTallyCircuit {
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
