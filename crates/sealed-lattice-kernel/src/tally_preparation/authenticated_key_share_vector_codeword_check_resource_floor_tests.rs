use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_OPTION_COUNT,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_share_vector_codeword_check_resource_floor::AuthenticatedKeyShareVectorCodewordCheckResourceFloor,
};

#[test]
fn completion_codeword_check_work_and_live_bytes_are_exact() {
    let circuit = completion_profile_circuit();
    let model = AuthenticatedKeyShareVectorCodewordCheckResourceFloor::derive(
        context(0x51, &circuit),
        &circuit,
    )
    .unwrap();

    assert_eq!(
        model,
        AuthenticatedKeyShareVectorCodewordCheckResourceFloor {
            participant_count: 10,
            basis_participant_count: 4,
            nonbasis_participant_count: 6,
            verification_key_field_element_count: 1_443_180,
            share_vector_chunk_count: 45,
            checked_share_vector_count: 10,
            checked_payload_byte_length: 461_817_600,
            decoded_field_element_count: 14_431_800,
            reconstructed_field_element_count: 1_443_180,
            reconstructed_key_byte_length: 46_181_760,
            payload_chunk_hash_invocation_count: 450,
            payload_chunk_hash_absorbed_byte_length: 462_000_300,
            payload_chunk_hash_output_byte_length: 28_800,
            payload_chunk_hash_fixed_keccak_f1600_permutation_count: 3_397_460,
            maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count: 7_714,
            interpolation_coefficient_vector_count: 7,
            field_multiplication_count: 40_409_320,
            field_addition_count: 40_409_208,
            field_inversion_count: 7,
            constant_time_comparison_count: 8_659_080,
            maximum_simultaneous_payload_chunk_count: 1,
            maximum_retained_basis_field_chunk_count: 4,
            maximum_output_field_chunk_count: 1,
            maximum_payload_and_field_buffer_count: 5,
            maximum_payload_chunk_byte_length: 1_048_576,
            single_copied_buffer_absolute_bound: 8_388_608,
            maximum_single_copied_buffer_headroom: 7_340_032,
            maximum_algorithm_live_payload_and_field_byte_length: 5_242_880,
        }
    );
    assert_eq!(
        core::mem::size_of::<BinaryFieldElement256>(),
        BinaryFieldElement256::CANONICAL_BYTE_LENGTH
    );
    assert_eq!(
        model.maximum_algorithm_live_payload_and_field_byte_length,
        model.maximum_payload_and_field_buffer_count * model.maximum_payload_chunk_byte_length
    );
    assert!(model.maximum_payload_chunk_byte_length <= model.single_copied_buffer_absolute_bound);
}

#[test]
fn every_threshold_four_shape_derives_codeword_work_without_completion_constants() {
    for participant_count in 9..=11 {
        for option_count in MINIMUM_CONFIGURABLE_OPTION_COUNT..=MAXIMUM_CONFIGURABLE_OPTION_COUNT {
            for top_count in 1..=option_count {
                let circuit = CompiledTallyCircuit::compile(
                    TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
                )
                .unwrap();
                let model = AuthenticatedKeyShareVectorCodewordCheckResourceFloor::derive(
                    context(u8::try_from(top_count).unwrap(), &circuit),
                    &circuit,
                )
                .unwrap();
                let nonbasis_participant_count = u64::from(participant_count - 4);
                let coefficient_vector_count = nonbasis_participant_count + 1;
                assert_eq!(model.participant_count, u64::from(participant_count));
                assert_eq!(model.basis_participant_count, 4);
                assert_eq!(model.nonbasis_participant_count, nonbasis_participant_count);
                assert_eq!(
                    model.interpolation_coefficient_vector_count,
                    coefficient_vector_count
                );
                assert_eq!(
                    model.constant_time_comparison_count,
                    model.verification_key_field_element_count * nonbasis_participant_count
                );
                assert_eq!(model.maximum_simultaneous_payload_chunk_count, 1);
                assert_eq!(model.maximum_retained_basis_field_chunk_count, 4);
                assert_eq!(model.maximum_payload_and_field_buffer_count, 5);
                assert_eq!(
                    model.checked_payload_byte_length,
                    model.participant_count
                        * model.verification_key_field_element_count
                        * BinaryFieldElement256::CANONICAL_BYTE_LENGTH as u64
                );
            }
        }
    }
}

#[test]
fn non_threshold_four_profiles_are_refused_before_codeword_resource_claims() {
    for participant_count in [8, 12] {
        let circuit = CompiledTallyCircuit::compile(
            TallyCircuitProfile::new(participant_count, 2, 1).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            AuthenticatedKeyShareVectorCodewordCheckResourceFloor::derive(
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

#[test]
fn completion_buffer_limits_are_imported_from_the_foundation_profile() {
    let circuit = completion_profile_circuit();
    let model = AuthenticatedKeyShareVectorCodewordCheckResourceFloor::derive(
        context(0x64, &circuit),
        &circuit,
    )
    .unwrap();
    assert_eq!(
        model.maximum_payload_chunk_byte_length,
        FOUNDATION_PROFILE.stream_chunk_byte_length as u64
    );
    assert_eq!(
        model.single_copied_buffer_absolute_bound,
        FOUNDATION_PROFILE.maximum_copied_buffer_byte_length as u64
    );
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
