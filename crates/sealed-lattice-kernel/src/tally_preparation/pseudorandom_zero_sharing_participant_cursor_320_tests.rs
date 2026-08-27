use tiny_keccak::{Hasher, Kmac};
use zeroize::Zeroizing;

use crate::{
    foundation::{FOUNDATION_PROFILE, Hash512},
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    TallyPreparationContext,
    binary_field_320::BinaryFieldElement320,
    pseudorandom_zero_sharing_320::{
        PerBitPseudorandomZeroSharingWorkload320, canonical_evaluation_point_320,
        evaluate_pseudorandom_zero_sharing_subset_at_point,
    },
    pseudorandom_zero_sharing_field_stream_320::{
        PseudorandomZeroSharingFieldStreamCoordinate320,
        generate_pseudorandom_zero_sharing_field_chunk_320,
    },
    pseudorandom_zero_sharing_participant_cursor_320::{
        PseudorandomZeroSharingCursorError320, PseudorandomZeroSharingCursorResourceModel320,
        PseudorandomZeroSharingCursorState320, PseudorandomZeroSharingParticipantCursor320,
    },
    pseudorandom_zero_sharing_seed_master_join_320::{
        LocallyJoinedPseudorandomZeroSharingSubsetMaster320, locally_joined_subset_master_for_test,
    },
    pseudorandom_zero_sharing_subset_seed_320::PseudorandomZeroSharingSubsetMasterScope320,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

const PARAMETER_IDENTITY_BYTES: [u8; 64] = [0x31; 64];
const ZERO_SHARING_CATALOG_IDENTITY_BYTES: [u8; 64] = [0x53; 64];

#[test]
fn completion_graph_derives_the_retained_per_bit_zero_sharing_workload() {
    let circuit = completion_circuit();
    let workload = PerBitPseudorandomZeroSharingWorkload320::derive(&circuit).unwrap();

    assert_eq!(workload.independent_label_semantic_mask_count, 13_911);
    assert_eq!(workload.output_mask_count, 41);
    assert_eq!(workload.accepted_authorship_bit_count, 10);
    assert_eq!(workload.hidden_value_count, 13_962);
    assert_eq!(workload.hidden_value_product_count, 27_924);
    assert_eq!(workload.conjunction_product_count, 5_422);
    assert_eq!(workload.zero_sharing_count, 33_346);
    assert_eq!(
        workload
            .resource_input(FOUNDATION_PROFILE.participant_count)
            .zero_sharing_count,
        workload.zero_sharing_count
    );
}

#[test]
fn completion_cursor_resource_model_derives_exact_work_and_checkpoint_counts() {
    let workload = PerBitPseudorandomZeroSharingWorkload320::derive(&completion_circuit()).unwrap();
    let model = PseudorandomZeroSharingCursorResourceModel320::derive(
        FOUNDATION_PROFILE.participant_count,
        0,
        workload.zero_sharing_count,
    )
    .unwrap();

    assert_eq!(model.participant_count, 10);
    assert_eq!(model.authorized_subset_count_per_participant, 84);
    assert_eq!(model.basis_position_count_per_subset, 3);
    assert_eq!(model.basis_stream_count, 252);
    assert_eq!(model.zero_sharing_count, 33_346);
    assert_eq!(model.field_output_count, 8_403_192);
    assert_eq!(model.output_chunk_count, 2);
    assert_eq!(model.work_checkpoint_count, 504);
    assert_eq!(model.field_stream_kmacxof256_query_count, 504);
    assert_eq!(model.checkpoint_key_derivation_kmac256_count, 1);
    assert_eq!(model.checkpoint_tag_generation_kmac256_count, 504);
    assert_eq!(
        model.cold_restore_checkpoint_tag_verification_kmac256_count,
        1
    );
    assert_eq!(model.basis_precomputation_field_multiplication_count, 420);
    assert_eq!(model.combination_field_multiplication_count, 8_403_192);
    assert_eq!(model.combination_field_addition_count, 8_369_846);
    assert_eq!(model.full_chunk_field_count, 26_214);
    assert_eq!(model.final_chunk_field_count, 7_132);
    assert_eq!(model.full_chunk_payload_byte_length, 1_048_560);
    assert_eq!(model.final_chunk_payload_byte_length, 285_280);
    assert_eq!(model.minimum_completed_step_checkpoint_byte_length, 285_625);
    assert_eq!(
        model.maximum_completed_step_checkpoint_byte_length,
        1_048_906
    );
    assert_eq!(
        model.cumulative_completed_step_checkpoint_byte_length,
        336_301_810
    );
    assert_eq!(
        model.cumulative_checkpoint_authenticated_body_byte_length,
        336_269_554
    );
    assert!(
        model.maximum_completed_step_checkpoint_byte_length
            <= u64::try_from(FOUNDATION_PROFILE.maximum_copied_buffer_byte_length).unwrap()
    );
    assert_eq!(
        model.cumulative_checkpoint_authenticated_body_byte_length
            + model.work_checkpoint_count * 64,
        model.cumulative_completed_step_checkpoint_byte_length
    );
}

#[test]
fn cursor_matches_an_independent_subset_evaluator_and_resumes_every_boundary() {
    let fixture = cursor_fixture(7);
    let mut uninterrupted = fixture.cursor();
    let independent_output = independently_evaluate_output(&fixture);
    let mut checkpoints = Vec::new();
    let mut observed_checkpoint_byte_length = 0_u64;

    while uninterrupted.state() == PseudorandomZeroSharingCursorState320::Processing {
        uninterrupted.step(&fixture.masters).unwrap();
        let checkpoint = uninterrupted.checkpoint_bytes().unwrap();
        observed_checkpoint_byte_length += u64::try_from(checkpoint.len()).unwrap();
        checkpoints.push(checkpoint);
    }
    let uninterrupted_output = uninterrupted.completed_chunk_bytes().unwrap();
    assert_eq!(
        uninterrupted_output.as_slice(),
        independent_output.as_slice()
    );

    let resource_model = PseudorandomZeroSharingCursorResourceModel320::derive(
        fixture.context.participant_count(),
        fixture.participant_position,
        fixture.total_field_count,
    )
    .unwrap();
    assert_eq!(resource_model.work_checkpoint_count, 3);
    assert_eq!(
        observed_checkpoint_byte_length,
        resource_model.cumulative_completed_step_checkpoint_byte_length
    );
    assert_eq!(
        checkpoints.iter().map(|bytes| bytes.len()).min().unwrap() as u64,
        resource_model.minimum_completed_step_checkpoint_byte_length
    );
    assert_eq!(
        checkpoints.iter().map(|bytes| bytes.len()).max().unwrap() as u64,
        resource_model.maximum_completed_step_checkpoint_byte_length
    );

    for checkpoint in checkpoints {
        let mut resumed = fixture.restore(&checkpoint).unwrap();
        while resumed.state() == PseudorandomZeroSharingCursorState320::Processing {
            resumed.step(&fixture.masters).unwrap();
        }
        assert_eq!(
            resumed.completed_chunk_bytes().unwrap().as_slice(),
            independent_output.as_slice()
        );
    }

    assert_eq!(
        uninterrupted.acknowledge_completed_chunk().unwrap(),
        PseudorandomZeroSharingCursorState320::Finished
    );
    assert_eq!(
        uninterrupted.step(&fixture.masters).unwrap_err(),
        PseudorandomZeroSharingCursorError320::CursorNotProcessing {
            state: PseudorandomZeroSharingCursorState320::Finished,
        }
    );
}

#[test]
fn checkpoint_authentication_matches_independent_kmac_and_refuses_mutation() {
    let fixture = cursor_fixture(5);
    let mut cursor = fixture.cursor();
    cursor.step(&fixture.masters).unwrap();
    let checkpoint = cursor.checkpoint_bytes().unwrap();
    let body_byte_length = checkpoint.len() - 64;
    let (body, actual_tag) = checkpoint.split_at(body_byte_length);

    let expected_key = independently_derive_checkpoint_key(&fixture);
    let mut expected_tag = Zeroizing::new([0_u8; 64]);
    let mut tag_kmac = Kmac::v256(
        expected_key.as_ref(),
        b"sealed-lattice/v1/preparation/pseudorandom-zero-sharing-checkpoint-tag",
    );
    tag_kmac.update(body);
    tag_kmac.finalize(expected_tag.as_mut());
    assert_eq!(actual_tag, expected_tag.as_slice());

    for mutated_position in [0, body.len() / 2, body.len() - 1, checkpoint.len() - 1] {
        let mut mutated = checkpoint.to_vec();
        mutated[mutated_position] ^= 1;
        assert_eq!(
            fixture.restore(&mutated).unwrap_err(),
            PseudorandomZeroSharingCursorError320::CheckpointAuthenticationFailed
        );
    }
    for malformed in [checkpoint[..checkpoint.len() - 1].to_vec(), {
        let mut trailing = checkpoint.to_vec();
        trailing.push(0);
        trailing
    }] {
        assert!(matches!(
            fixture.restore(&malformed),
            Err(PseudorandomZeroSharingCursorError320::CheckpointAuthenticationFailed)
                | Err(PseudorandomZeroSharingCursorError320::CheckpointEncoding)
        ));
    }
}

#[test]
fn cursor_refuses_missing_reordered_and_wrong_scope_masters() {
    let missing_fixture = cursor_fixture(3);
    assert_eq!(
        PseudorandomZeroSharingParticipantCursor320::new(
            missing_fixture.parameter_identity,
            missing_fixture.context,
            missing_fixture.zero_sharing_catalog_identity,
            missing_fixture.participant_position,
            missing_fixture.total_field_count,
            &missing_fixture.masters[..missing_fixture.masters.len() - 1],
        )
        .unwrap_err(),
        PseudorandomZeroSharingCursorError320::MasterCountMismatch {
            expected: 3,
            actual: 2,
        }
    );

    let mut reordered_fixture = cursor_fixture(3);
    reordered_fixture.masters.swap(0, 1);
    assert_eq!(
        PseudorandomZeroSharingParticipantCursor320::new(
            reordered_fixture.parameter_identity,
            reordered_fixture.context,
            reordered_fixture.zero_sharing_catalog_identity,
            reordered_fixture.participant_position,
            reordered_fixture.total_field_count,
            &reordered_fixture.masters,
        )
        .unwrap_err(),
        PseudorandomZeroSharingCursorError320::MasterScopeMismatch { master_index: 0 }
    );

    let wrong_parameter_fixture = cursor_fixture(3);
    assert_eq!(
        PseudorandomZeroSharingParticipantCursor320::new(
            Hash512::from_bytes([0xa7; 64]),
            wrong_parameter_fixture.context,
            wrong_parameter_fixture.zero_sharing_catalog_identity,
            wrong_parameter_fixture.participant_position,
            wrong_parameter_fixture.total_field_count,
            &wrong_parameter_fixture.masters,
        )
        .unwrap_err(),
        PseudorandomZeroSharingCursorError320::MasterScopeMismatch { master_index: 0 }
    );
}

#[test]
fn cursor_debug_output_redacts_every_secret_buffer() {
    let fixture = cursor_fixture(2);
    let cursor = fixture.cursor();
    let debug_output = format!("{cursor:?}");

    assert!(debug_output.contains("[redacted]"));
    assert!(!debug_output.contains(&format!("{:02x?}", fixture.masters[0].as_bytes())));
}

struct CursorFixture {
    parameter_identity: Hash512,
    context: TallyPreparationContext,
    zero_sharing_catalog_identity: Hash512,
    participant_position: u16,
    total_field_count: u64,
    masters: Vec<LocallyJoinedPseudorandomZeroSharingSubsetMaster320>,
}

impl CursorFixture {
    fn cursor(&self) -> PseudorandomZeroSharingParticipantCursor320 {
        PseudorandomZeroSharingParticipantCursor320::new(
            self.parameter_identity,
            self.context,
            self.zero_sharing_catalog_identity,
            self.participant_position,
            self.total_field_count,
            &self.masters,
        )
        .unwrap()
    }

    fn restore(
        &self,
        checkpoint: &[u8],
    ) -> Result<PseudorandomZeroSharingParticipantCursor320, PseudorandomZeroSharingCursorError320>
    {
        PseudorandomZeroSharingParticipantCursor320::restore_from_checkpoint(
            self.parameter_identity,
            self.context,
            self.zero_sharing_catalog_identity,
            self.participant_position,
            self.total_field_count,
            &self.masters,
            checkpoint,
        )
    }
}

fn cursor_fixture(total_field_count: u64) -> CursorFixture {
    let participant_count = 4;
    let participant_position = 1;
    let circuit =
        CompiledTallyCircuit::compile(TallyCircuitProfile::new(participant_count, 2, 2).unwrap())
            .unwrap();
    let context = TallyPreparationContext::new(
        Hash512::from_bytes([0x11; 64]),
        Hash512::from_bytes([0x23; 64]),
        [0x47; 32],
        &circuit,
    )
    .unwrap();
    let parameter_identity = Hash512::from_bytes(PARAMETER_IDENTITY_BYTES);
    let zero_sharing_catalog_identity = Hash512::from_bytes(ZERO_SHARING_CATALOG_IDENTITY_BYTES);
    let masters = ReplicatedRandomSharingSubset::iter(participant_count)
        .unwrap()
        .filter(|subset| subset.contains(participant_position).unwrap())
        .enumerate()
        .map(|(master_index, subset)| {
            let scope = PseudorandomZeroSharingSubsetMasterScope320::new(
                parameter_identity,
                context,
                subset,
            )
            .unwrap();
            let bytes = core::array::from_fn(|byte_position| {
                1_u8.wrapping_add(u8::try_from(master_index * 43 + byte_position * 7).unwrap_or(0))
            });
            locally_joined_subset_master_for_test(scope, bytes)
        })
        .collect();
    CursorFixture {
        parameter_identity,
        context,
        zero_sharing_catalog_identity,
        participant_position,
        total_field_count,
        masters,
    }
}

fn independently_evaluate_output(fixture: &CursorFixture) -> Zeroizing<Vec<u8>> {
    let evaluation_point = canonical_evaluation_point_320(
        fixture.context.participant_count(),
        fixture.participant_position,
    )
    .unwrap();
    let mut output = vec![BinaryFieldElement320::ZERO; fixture.total_field_count as usize];
    for master in &fixture.masters {
        let subset = master.scope().subset();
        let component_chunks = (0..subset.active_fault_bound())
            .map(|basis_position| {
                let coordinate = PseudorandomZeroSharingFieldStreamCoordinate320::new(
                    fixture.parameter_identity,
                    fixture.context,
                    fixture.zero_sharing_catalog_identity,
                    subset,
                    basis_position,
                    fixture.total_field_count,
                )
                .unwrap();
                generate_pseudorandom_zero_sharing_field_chunk_320(master, coordinate, 0).unwrap()
            })
            .collect::<Vec<_>>();
        for field_position in 0..fixture.total_field_count {
            let components = component_chunks
                .iter()
                .map(|chunk| chunk.field_element(field_position).unwrap())
                .collect::<Vec<_>>();
            output[field_position as usize] = output[field_position as usize].add(
                evaluate_pseudorandom_zero_sharing_subset_at_point(
                    subset,
                    &components,
                    evaluation_point,
                )
                .unwrap(),
            );
        }
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(output.len() * 40));
    for field_element in output {
        bytes.extend_from_slice(&field_element.canonical_bytes());
    }
    bytes
}

fn independently_derive_checkpoint_key(fixture: &CursorFixture) -> Zeroizing<[u8; 40]> {
    let mut derivation = Kmac::v256(
        fixture.masters[0].as_bytes(),
        b"sealed-lattice/v1/preparation/pseudorandom-zero-sharing-checkpoint-key",
    );
    derivation.update(&1_u64.to_le_bytes());
    derivation.update(fixture.parameter_identity.as_bytes());
    derivation.update(fixture.context.identity().as_bytes());
    derivation.update(fixture.zero_sharing_catalog_identity.as_bytes());
    derivation.update(&fixture.context.participant_count().to_le_bytes());
    derivation.update(&fixture.participant_position.to_le_bytes());
    derivation.update(&(fixture.masters.len() as u64).to_le_bytes());
    for master in &fixture.masters {
        derivation.update(
            &master
                .scope()
                .subset()
                .excluded_position_mask()
                .to_le_bytes(),
        );
        derivation.update(master.as_bytes());
    }
    let mut key = Zeroizing::new([0_u8; 40]);
    derivation.finalize(key.as_mut());
    key
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
