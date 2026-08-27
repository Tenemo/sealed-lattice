use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    binary_field_320::BinaryFieldElement320,
    pseudorandom_zero_sharing_320::{
        CanonicalZeroSharingCodewordBlockVerification320,
        CanonicalZeroSharingCodewordBlockVerifier320,
    },
    pseudorandom_zero_sharing_measurement_fixture_320::derive_all_roster_zero_sharing_measurement_master_320,
    pseudorandom_zero_sharing_participant_cursor_320::{
        PseudorandomZeroSharingCursorState320, PseudorandomZeroSharingParticipantCursor320,
    },
    pseudorandom_zero_sharing_seed_master_join_320::{
        LocallyJoinedPseudorandomZeroSharingSubsetMaster320, locally_joined_subset_master_for_test,
    },
    pseudorandom_zero_sharing_subset_seed_320::PseudorandomZeroSharingSubsetMasterScope320,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

struct CodewordSourceFixture320 {
    parameter_identity: Hash512,
    preparation_context: TallyPreparationContext,
    zero_sharing_catalog_identity: Hash512,
    participant_position: u16,
    total_field_count: u64,
    masters: Box<[LocallyJoinedPseudorandomZeroSharingSubsetMaster320]>,
}

#[test]
fn all_roster_sources_form_field_major_rows_consumed_by_the_bounded_verifier() {
    let participant_count = FOUNDATION_PROFILE.participant_count;
    let field_count = 17_u64;
    let participant_outputs = (0..participant_count)
        .map(|participant_position| {
            collect_source_output(codeword_source_fixture(participant_position, field_count))
        })
        .collect::<Vec<_>>();
    let field_byte_length = BinaryFieldElement320::CANONICAL_BYTE_LENGTH;
    let expected_participant_output_byte_length =
        usize::try_from(field_count).unwrap() * field_byte_length;
    assert!(
        participant_outputs
            .iter()
            .all(|output| output.len() == expected_participant_output_byte_length)
    );

    let mut field_major_block = Vec::with_capacity(
        expected_participant_output_byte_length * usize::from(participant_count),
    );
    for field_position in 0..usize::try_from(field_count).unwrap() {
        let field_offset = field_position * field_byte_length;
        for participant_output in &participant_outputs {
            field_major_block.extend_from_slice(
                &participant_output[field_offset..field_offset + field_byte_length],
            );
        }
    }

    let verifier = CanonicalZeroSharingCodewordBlockVerifier320::new(participant_count).unwrap();
    assert_eq!(
        verifier
            .verify_field_major_block(&field_major_block)
            .unwrap(),
        CanonicalZeroSharingCodewordBlockVerification320 {
            codeword_count: field_count,
            is_valid: true,
        }
    );
    for participant_position in 0..usize::from(participant_count) {
        let mut invalid_block = field_major_block.clone();
        invalid_block[participant_position * field_byte_length] ^= 1;
        assert!(
            !verifier
                .verify_field_major_block(&invalid_block)
                .unwrap()
                .is_valid,
            "mutated roster position {participant_position}"
        );
    }
}

fn codeword_source_fixture(
    participant_position: u16,
    total_field_count: u64,
) -> CodewordSourceFixture320 {
    let circuit = CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(
            FOUNDATION_PROFILE.participant_count,
            FOUNDATION_PROFILE.option_count,
            FOUNDATION_PROFILE.option_count,
        )
        .unwrap(),
    )
    .unwrap();
    let preparation_context = TallyPreparationContext::new(
        Hash512::from_bytes([0x21; Hash512::BYTE_LENGTH]),
        Hash512::from_bytes([0x43; Hash512::BYTE_LENGTH]),
        [0x65; 32],
        &circuit,
    )
    .unwrap();
    let parameter_identity = Hash512::from_bytes([0x87; Hash512::BYTE_LENGTH]);
    let zero_sharing_catalog_identity = Hash512::from_bytes([0xa9; Hash512::BYTE_LENGTH]);
    let masters = ReplicatedRandomSharingSubset::iter(preparation_context.participant_count())
        .unwrap()
        .filter(|subset| subset.contains(participant_position).unwrap())
        .map(|subset| {
            let scope = PseudorandomZeroSharingSubsetMasterScope320::new(
                parameter_identity,
                preparation_context,
                subset,
            )
            .unwrap();
            let bytes = derive_all_roster_zero_sharing_measurement_master_320(
                parameter_identity,
                preparation_context.identity(),
                zero_sharing_catalog_identity,
                subset.excluded_position_mask(),
            );
            locally_joined_subset_master_for_test(scope, bytes)
        })
        .collect::<Vec<_>>()
        .into_boxed_slice();
    CodewordSourceFixture320 {
        parameter_identity,
        preparation_context,
        zero_sharing_catalog_identity,
        participant_position,
        total_field_count,
        masters,
    }
}

fn collect_source_output(fixture: CodewordSourceFixture320) -> Vec<u8> {
    let mut cursor = PseudorandomZeroSharingParticipantCursor320::new(
        fixture.parameter_identity,
        fixture.preparation_context,
        fixture.zero_sharing_catalog_identity,
        fixture.participant_position,
        fixture.total_field_count,
        &fixture.masters,
    )
    .unwrap();
    let mut output = Vec::new();
    while cursor.state() != PseudorandomZeroSharingCursorState320::Finished {
        cursor.step(&fixture.masters).unwrap();
        if cursor.state() == PseudorandomZeroSharingCursorState320::CompletedChunkReady {
            output.extend_from_slice(&cursor.completed_chunk_bytes().unwrap());
            cursor.acknowledge_completed_chunk().unwrap();
        }
    }
    output
}
