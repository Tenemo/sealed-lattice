use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    authenticated_key_release_resource_floor::AuthenticatedKeyReleaseResourceFloor,
    garbled_resource_model::GarbledTallyResourceLowerBound,
};

const FIELD_ELEMENT_BYTE_LENGTH: u64 = 32;

#[test]
fn completion_key_release_floor_corrects_the_reconstructed_key_undercount() {
    let circuit = completion_profile_circuit();
    let model =
        AuthenticatedKeyReleaseResourceFloor::derive(context(0x63, &circuit), &circuit).unwrap();

    assert_eq!(
        model,
        AuthenticatedKeyReleaseResourceFloor {
            participant_count: 10,
            reconstruction_threshold: 4,
            holder_record_count: 475_590,
            verification_key_field_element_count: 1_443_180,
            reconstructed_key_byte_length: 46_181_760,
            share_vector_byte_length_per_sender: 46_181_760,
            share_vector_chunk_count_per_sender: 45,
            final_share_vector_chunk_byte_length: 44_416,
            quorum_checked_share_sender_count: 4,
            quorum_checked_share_payload_byte_length: 184_727_040,
            quorum_checked_additional_byte_length: 138_545_280,
            all_roster_share_sender_count: 10,
            all_roster_share_payload_byte_length: 461_817_600,
            all_roster_additional_byte_length: 415_635_840,
        }
    );
}

#[test]
fn independent_completion_derivation_matches_the_production_floor() {
    let circuit = completion_profile_circuit();
    let resources = GarbledTallyResourceLowerBound::derive(&circuit).unwrap();
    let model =
        AuthenticatedKeyReleaseResourceFloor::derive(context(0x64, &circuit), &circuit).unwrap();

    let label_record_count = 1_230_u64 * 2 * 10 * 10;
    let scalar_record_count = 1_230_u64 * 10 + 5_422 * 4 * 10 + 41 * 10;
    let independent_key_field_element_count = label_record_count * 4 + scalar_record_count * 2;
    assert_eq!(independent_key_field_element_count, 1_443_180);
    assert_eq!(
        independent_key_field_element_count,
        resources.dkac_verification_key_field_element_count
    );
    assert_eq!(
        model.reconstructed_key_byte_length,
        independent_key_field_element_count * FIELD_ELEMENT_BYTE_LENGTH
    );
    assert_eq!(
        model.quorum_checked_share_payload_byte_length,
        model.reconstruction_threshold * model.reconstructed_key_byte_length
    );
    assert_eq!(
        model.all_roster_share_payload_byte_length,
        model.participant_count * model.reconstructed_key_byte_length
    );
}

#[test]
fn every_admitted_shape_derives_thresholds_and_key_widths_from_canonical_owners() {
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
                let resources = GarbledTallyResourceLowerBound::derive(&circuit).unwrap();
                let model = AuthenticatedKeyReleaseResourceFloor::derive(
                    context(u8::try_from(top_count).unwrap(), &circuit),
                    &circuit,
                )
                .unwrap();

                assert_eq!(model.participant_count, u64::from(participant_count));
                assert_eq!(
                    model.reconstruction_threshold,
                    u64::from(roster_parameters.reconstruction_threshold)
                );
                assert_eq!(
                    model.holder_record_count,
                    resources.total_share_record_count
                );
                assert_eq!(
                    model.verification_key_field_element_count,
                    resources.dkac_verification_key_field_element_count
                );
                assert_eq!(
                    model.reconstructed_key_byte_length,
                    resources.dkac_verification_key_byte_length
                );
                assert_eq!(
                    model.quorum_checked_share_sender_count,
                    model.reconstruction_threshold
                );
                assert_eq!(model.all_roster_share_sender_count, model.participant_count);
                assert!(model.final_share_vector_chunk_byte_length > 0);
                assert!(
                    model.final_share_vector_chunk_byte_length
                        <= u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length).unwrap()
                );
            }
        }
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
