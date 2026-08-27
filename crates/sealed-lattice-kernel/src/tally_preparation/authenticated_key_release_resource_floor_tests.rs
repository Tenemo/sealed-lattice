use crate::{
    foundation::{
        FOUNDATION_PROFILE, Hash512, MAXIMUM_CONFIGURABLE_OPTION_COUNT,
        MAXIMUM_CONFIGURABLE_PARTICIPANT_COUNT, MINIMUM_CONFIGURABLE_OPTION_COUNT,
        MINIMUM_CONFIGURABLE_PARTICIPANT_COUNT, derive_foundation_roster_parameters,
    },
    tally_circuit::{BooleanOperation, CompiledTallyCircuit, TallyCircuitProfile},
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
            holder_record_count: 204_990,
            verification_key_field_element_count: 573_980,
            reconstructed_key_byte_length: 18_367_360,
            share_vector_byte_length_per_sender: 18_367_360,
            share_vector_chunk_count_per_sender: 18,
            final_share_vector_chunk_byte_length: 541_568,
            share_vector_descriptor_byte_length_per_sender: 1_506,
            payload_chunk_hash_invocation_count_per_sender: 18,
            payload_chunk_hash_absorbed_byte_length_per_sender: 18_374_668,
            payload_chunk_hash_output_byte_length_per_sender: 1_152,
            payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender: 135_124,
            maximum_payload_chunk_hash_fixed_keccak_f1600_permutation_count: 7_714,
            quorum_checked_share_sender_count: 4,
            quorum_checked_share_payload_byte_length: 73_469_440,
            quorum_checked_share_descriptor_byte_length: 6_024,
            quorum_checked_share_payload_and_descriptor_byte_length: 73_475_464,
            quorum_checked_share_manifest_byte_length: 651,
            acknowledgement_body_byte_length_per_participant: 130,
            all_roster_acknowledgement_body_byte_length: 1_300,
            quorum_checked_share_control_byte_length: 7_975,
            quorum_checked_share_payload_and_control_byte_length: 73_477_415,
            quorum_checked_additional_byte_length: 55_110_055,
            all_roster_share_sender_count: 10,
            all_roster_share_payload_byte_length: 183_673_600,
            all_roster_share_descriptor_byte_length: 15_060,
            all_roster_share_payload_and_descriptor_byte_length: 183_688_660,
            all_roster_share_manifest_byte_length: 1_056,
            all_roster_share_control_byte_length: 16_116,
            all_roster_share_payload_and_control_byte_length: 183_689_716,
            all_roster_additional_byte_length: 165_322_356,
        }
    );
}

#[test]
fn independent_completion_derivation_matches_the_production_floor() {
    let circuit = completion_profile_circuit();
    let resources = GarbledTallyResourceLowerBound::derive(&circuit).unwrap();
    let model =
        AuthenticatedKeyReleaseResourceFloor::derive(context(0x64, &circuit), &circuit).unwrap();

    let participant_count = u64::from(circuit.profile().participant_count());
    let input_bit_count = u64::try_from(circuit.geometry().input_bit_count).unwrap();
    let conjunction_gate_count = u64::try_from(
        circuit
            .operations()
            .iter()
            .filter(|operation| matches!(operation, BooleanOperation::Conjunction { .. }))
            .count(),
    )
    .unwrap();
    let output_mask_count = u64::try_from(
        circuit.geometry().public_output_bit_count + circuit.geometry().private_result_bit_count,
    )
    .unwrap();
    let label_record_count = input_bit_count * 2 * participant_count * participant_count;
    let scalar_record_count = input_bit_count * participant_count
        + conjunction_gate_count * 4 * participant_count
        + output_mask_count * participant_count;
    let independent_key_field_element_count = label_record_count * 4 + scalar_record_count * 2;
    assert_eq!(independent_key_field_element_count, 573_980);
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
    let descriptor_magic_byte_length =
        b"sealed-lattice/authenticated-key-share-vector-descriptor".len() as u64;
    let framed_hash_byte_length = 1 + 64;
    let independent_descriptor_byte_length = varuint_byte_length(descriptor_magic_byte_length)
        + descriptor_magic_byte_length
        + varuint_byte_length(1)
        + 4 * framed_hash_byte_length
        + varuint_byte_length(model.participant_count)
        + varuint_byte_length(0)
        + varuint_byte_length(model.verification_key_field_element_count)
        + varuint_byte_length(FIELD_ELEMENT_BYTE_LENGTH)
        + varuint_byte_length(FOUNDATION_PROFILE.stream_chunk_byte_length as u64)
        + varuint_byte_length(model.share_vector_byte_length_per_sender)
        + varuint_byte_length(model.share_vector_chunk_count_per_sender)
        + varuint_byte_length(model.final_share_vector_chunk_byte_length)
        + varuint_byte_length(model.share_vector_chunk_count_per_sender)
        + model.share_vector_chunk_count_per_sender * framed_hash_byte_length;
    assert_eq!(
        independent_descriptor_byte_length,
        model.share_vector_descriptor_byte_length_per_sender
    );
    let hash_preimage_fixed_byte_length = 19
        + framed_byte_length(62)
        + varuint_byte_length(13)
        + 4 * framed_hash_byte_length
        + 2 * framed_byte_length(2)
        + 6 * framed_byte_length(8);
    let complete_chunk_query_byte_length = hash_preimage_fixed_byte_length
        + framed_byte_length(FOUNDATION_PROFILE.stream_chunk_byte_length as u64);
    let final_chunk_query_byte_length = hash_preimage_fixed_byte_length
        + framed_byte_length(model.final_share_vector_chunk_byte_length);
    assert_eq!(
        model.payload_chunk_hash_absorbed_byte_length_per_sender,
        (model.share_vector_chunk_count_per_sender - 1) * complete_chunk_query_byte_length
            + final_chunk_query_byte_length
    );
    assert_eq!(
        model.payload_chunk_hash_output_byte_length_per_sender,
        model.payload_chunk_hash_invocation_count_per_sender * 64
    );
    assert_eq!(
        model.payload_chunk_hash_fixed_keccak_f1600_permutation_count_per_sender,
        (model.share_vector_chunk_count_per_sender - 1)
            * (complete_chunk_query_byte_length / 136 + 1)
            + (final_chunk_query_byte_length / 136 + 1)
    );
    assert_eq!(
        model.quorum_checked_share_descriptor_byte_length,
        model.reconstruction_threshold * independent_descriptor_byte_length
    );
    assert_eq!(
        model.quorum_checked_share_payload_and_descriptor_byte_length,
        model.quorum_checked_share_payload_byte_length
            + model.quorum_checked_share_descriptor_byte_length
    );
    let manifest_magic_byte_length =
        b"sealed-lattice/authenticated-key-share-vector-manifest".len() as u64;
    let independent_manifest_byte_length = varuint_byte_length(manifest_magic_byte_length)
        + manifest_magic_byte_length
        + varuint_byte_length(1)
        + 5 * framed_hash_byte_length
        + varuint_byte_length(model.participant_count)
        + varuint_byte_length(model.reconstruction_threshold)
        + varuint_byte_length(model.verification_key_field_element_count)
        + varuint_byte_length(model.reconstruction_threshold)
        + (0..model.reconstruction_threshold)
            .map(|sender_position| varuint_byte_length(sender_position) + framed_hash_byte_length)
            .sum::<u64>();
    assert_eq!(
        model.quorum_checked_share_manifest_byte_length,
        independent_manifest_byte_length
    );
    let acknowledgement_magic_byte_length =
        b"sealed-lattice/authenticated-key-share-vector-acknowledgement".len() as u64;
    let independent_acknowledgement_body_byte_length = |participant_position| {
        varuint_byte_length(acknowledgement_magic_byte_length)
            + acknowledgement_magic_byte_length
            + varuint_byte_length(1)
            + framed_hash_byte_length
            + varuint_byte_length(model.participant_count)
            + varuint_byte_length(participant_position)
    };
    assert_eq!(
        model.acknowledgement_body_byte_length_per_participant,
        independent_acknowledgement_body_byte_length(0)
    );
    assert_eq!(
        model.all_roster_acknowledgement_body_byte_length,
        (0..model.participant_count)
            .map(independent_acknowledgement_body_byte_length)
            .sum::<u64>()
    );
    assert_eq!(
        model.quorum_checked_share_control_byte_length,
        model.quorum_checked_share_descriptor_byte_length
            + model.quorum_checked_share_manifest_byte_length
            + model.all_roster_acknowledgement_body_byte_length
    );
    assert_eq!(
        model.quorum_checked_share_payload_and_control_byte_length,
        model.quorum_checked_share_payload_byte_length
            + model.quorum_checked_share_control_byte_length
    );
    assert_eq!(
        model.quorum_checked_additional_byte_length,
        model.quorum_checked_share_payload_and_control_byte_length
            - model.reconstructed_key_byte_length
    );
    assert_eq!(
        model.all_roster_share_payload_byte_length,
        model.participant_count * model.reconstructed_key_byte_length
    );
    assert_eq!(
        model.all_roster_share_descriptor_byte_length,
        model.participant_count * independent_descriptor_byte_length
    );
    assert_eq!(
        model.all_roster_share_payload_and_descriptor_byte_length,
        model.all_roster_share_payload_byte_length + model.all_roster_share_descriptor_byte_length
    );
    let codeword_manifest_magic_byte_length =
        b"sealed-lattice/authenticated-key-share-vector-codeword-manifest".len() as u64;
    let independent_codeword_manifest_byte_length =
        varuint_byte_length(codeword_manifest_magic_byte_length)
            + codeword_manifest_magic_byte_length
            + varuint_byte_length(1)
            + 5 * framed_hash_byte_length
            + varuint_byte_length(model.participant_count)
            + varuint_byte_length(model.reconstruction_threshold)
            + varuint_byte_length(model.verification_key_field_element_count)
            + varuint_byte_length(model.participant_count)
            + (0..model.participant_count)
                .map(|sender_position| {
                    varuint_byte_length(sender_position) + framed_hash_byte_length
                })
                .sum::<u64>();
    assert_eq!(
        model.all_roster_share_manifest_byte_length,
        independent_codeword_manifest_byte_length
    );
    assert_eq!(
        model.all_roster_share_control_byte_length,
        model.all_roster_share_descriptor_byte_length + model.all_roster_share_manifest_byte_length
    );
    assert_eq!(
        model.all_roster_share_payload_and_control_byte_length,
        model.all_roster_share_payload_byte_length + model.all_roster_share_control_byte_length
    );
    assert_eq!(
        model.all_roster_additional_byte_length,
        model.all_roster_share_payload_and_control_byte_length
            - model.reconstructed_key_byte_length
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
                assert_eq!(
                    model.quorum_checked_share_control_byte_length,
                    model.quorum_checked_share_descriptor_byte_length
                        + model.quorum_checked_share_manifest_byte_length
                        + model.all_roster_acknowledgement_body_byte_length
                );
                assert_eq!(
                    model.quorum_checked_share_payload_and_control_byte_length,
                    model.quorum_checked_share_payload_byte_length
                        + model.quorum_checked_share_control_byte_length
                );
                assert_eq!(
                    model.all_roster_acknowledgement_body_byte_length,
                    model.participant_count
                        * model.acknowledgement_body_byte_length_per_participant
                );
                assert_eq!(model.all_roster_share_sender_count, model.participant_count);
                assert_eq!(
                    model.all_roster_share_control_byte_length,
                    model.all_roster_share_descriptor_byte_length
                        + model.all_roster_share_manifest_byte_length
                );
                assert_eq!(
                    model.all_roster_share_payload_and_control_byte_length,
                    model.all_roster_share_payload_byte_length
                        + model.all_roster_share_control_byte_length
                );
                assert_eq!(
                    model.all_roster_additional_byte_length,
                    model.all_roster_share_payload_and_control_byte_length
                        - model.reconstructed_key_byte_length
                );
                assert!(
                    model.share_vector_descriptor_byte_length_per_sender
                        <= u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length).unwrap()
                );
                assert!(model.final_share_vector_chunk_byte_length > 0);
                assert!(
                    model.final_share_vector_chunk_byte_length
                        <= u64::try_from(FOUNDATION_PROFILE.stream_chunk_byte_length).unwrap()
                );
            }
        }
    }
}

fn varuint_byte_length(mut value: u64) -> u64 {
    let mut byte_length = 1_u64;
    while value >= 128 {
        value >>= 7;
        byte_length += 1;
    }
    byte_length
}

fn framed_byte_length(payload_byte_length: u64) -> u64 {
    varuint_byte_length(payload_byte_length) + payload_byte_length
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
