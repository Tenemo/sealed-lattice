use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_OPTION_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext, TallyPreparationError,
    authenticated_key_release::{
        AuthenticatedKeyFieldLocalCheckWork, AuthenticatedKeyFieldLocalChecker,
    },
    authenticated_key_share_vector_local_check_resource_floor::AuthenticatedKeyShareVectorLocalCheckResourceFloor,
};

#[test]
fn completion_local_check_resource_floor_is_exact() {
    let circuit = completion_profile_circuit();
    let model = AuthenticatedKeyShareVectorLocalCheckResourceFloor::derive(
        context(0x61, &circuit),
        &circuit,
    )
    .unwrap();

    assert_eq!(
        model,
        AuthenticatedKeyShareVectorLocalCheckResourceFloor {
            participant_count: 10,
            basis_participant_count: 4,
            nonbasis_participant_count: 6,
            verification_key_field_element_count: 573_980,
            share_vector_chunk_count: 18,
            checked_share_vector_count_per_participant: 5,
            checked_payload_byte_length_per_participant: 91_836_800,
            checked_payload_byte_length_all_participants: 918_368_000,
            decoded_field_element_count_per_participant: 2_869_900,
            decoded_field_element_count_all_participants: 28_699_000,
            reconstructed_field_element_count_per_participant: 573_980,
            reconstructed_key_byte_length_per_participant: 18_367_360,
            payload_chunk_hash_invocation_count_per_participant: 90,
            payload_chunk_hash_invocation_count_all_participants: 900,
            payload_chunk_hash_absorbed_byte_length_per_participant: 91_873_340,
            payload_chunk_hash_absorbed_byte_length_all_participants: 918_733_400,
            payload_chunk_hash_output_byte_length_per_participant: 5_760,
            payload_chunk_hash_output_byte_length_all_participants: 57_600,
            payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_participant: 675_620,
            payload_chunk_hash_fixed_keccak_f1600_permutation_count_all_participants: 6_756_200,
            maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count: 7_714,
            basis_participant_field_multiplication_count: 2_295_960,
            basis_participant_field_addition_count: 2_295_944,
            basis_participant_field_inversion_count: 1,
            nonbasis_participant_field_multiplication_count: 4_591_920,
            nonbasis_participant_field_addition_count: 4_591_888,
            nonbasis_participant_field_inversion_count: 2,
            all_participant_field_multiplication_count: 36_735_360,
            all_participant_field_addition_count: 36_735_104,
            all_participant_field_inversion_count: 16,
            all_participant_constant_time_comparison_count: 5_739_800,
            maximum_simultaneous_payload_chunk_count: 2,
            maximum_field_accumulator_count: 2,
            maximum_payload_chunk_byte_length: 1_048_576,
            single_copied_buffer_absolute_bound: 8_388_608,
            maximum_single_copied_buffer_headroom: 7_340_032,
            maximum_algorithm_live_payload_and_accumulator_byte_length: 3_145_728,
        }
    );
}

#[test]
fn independent_work_derivation_matches_basis_and_nonbasis_paths() {
    let basis_work = AuthenticatedKeyFieldLocalChecker::new(10, 3)
        .unwrap()
        .exact_work();
    let nonbasis_work = AuthenticatedKeyFieldLocalChecker::new(10, 4)
        .unwrap()
        .exact_work();
    assert_eq!(
        basis_work,
        AuthenticatedKeyFieldLocalCheckWork {
            coefficient_vector_count: 1,
            coefficient_precomputation_field_multiplication_count: 40,
            coefficient_precomputation_field_addition_count: 24,
            coefficient_precomputation_field_inversion_count: 1,
            field_multiplication_count_per_checked_field: 4,
            field_addition_count_per_checked_field: 4,
            constant_time_comparison_count_per_checked_field: 1,
        }
    );
    assert_eq!(
        nonbasis_work,
        AuthenticatedKeyFieldLocalCheckWork {
            coefficient_vector_count: 2,
            coefficient_precomputation_field_multiplication_count: 80,
            coefficient_precomputation_field_addition_count: 48,
            coefficient_precomputation_field_inversion_count: 2,
            field_multiplication_count_per_checked_field: 8,
            field_addition_count_per_checked_field: 8,
            constant_time_comparison_count_per_checked_field: 1,
        }
    );

    let circuit = completion_profile_circuit();
    let model = AuthenticatedKeyShareVectorLocalCheckResourceFloor::derive(
        context(0x62, &circuit),
        &circuit,
    )
    .unwrap();
    let field_count = model.verification_key_field_element_count;
    assert_eq!(
        model.basis_participant_field_multiplication_count,
        40 + field_count * 4
    );
    assert_eq!(
        model.basis_participant_field_addition_count,
        24 + field_count * 4
    );
    assert_eq!(
        model.nonbasis_participant_field_multiplication_count,
        80 + field_count * 8
    );
    assert_eq!(
        model.nonbasis_participant_field_addition_count,
        48 + field_count * 8
    );
    assert_eq!(
        model.all_participant_field_multiplication_count,
        4 * model.basis_participant_field_multiplication_count
            + 6 * model.nonbasis_participant_field_multiplication_count
    );
    assert_eq!(
        model.maximum_algorithm_live_payload_and_accumulator_byte_length,
        3 * model.maximum_payload_chunk_byte_length
    );
    assert!(model.maximum_payload_chunk_byte_length <= model.single_copied_buffer_absolute_bound);
}

#[test]
fn every_threshold_four_shape_derives_without_profile_constants() {
    for participant_count in 9..=11 {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let model = AuthenticatedKeyShareVectorLocalCheckResourceFloor::derive(
                    context(u8::try_from(top_count).unwrap(), &circuit),
                    &circuit,
                )
                .unwrap();
                assert_eq!(model.participant_count, u64::from(participant_count));
                assert_eq!(model.basis_participant_count, 4);
                assert_eq!(
                    model.nonbasis_participant_count,
                    u64::from(participant_count - 4)
                );
                assert_eq!(model.checked_share_vector_count_per_participant, 5);
                assert_eq!(model.maximum_simultaneous_payload_chunk_count, 2);
                assert_eq!(model.maximum_field_accumulator_count, 2);
                assert!(
                    model.maximum_payload_chunk_byte_length
                        <= model.single_copied_buffer_absolute_bound
                );
            }
        }
    }
}

#[test]
fn non_threshold_four_profiles_are_refused_before_resource_claims() {
    for participant_count in [8, 12] {
        let circuit = CompiledTallyCircuit::compile(
            TallyCircuitProfile::new(participant_count, 2, 1).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            AuthenticatedKeyShareVectorLocalCheckResourceFloor::derive(
                context(0x63, &circuit),
                &circuit,
            ),
            Err(TallyPreparationError::AuthenticatedKeyReleaseProfileMismatch { .. })
        ));
    }
}

fn context(marker: u8, circuit: &CompiledTallyCircuit) -> TallyPreparationContext {
    TallyPreparationContext::new(
        Hash512::from_bytes([0x71; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x82; Hash512::BYTE_LENGTH]),
        [marker; 32],
        circuit,
    )
    .unwrap()
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
