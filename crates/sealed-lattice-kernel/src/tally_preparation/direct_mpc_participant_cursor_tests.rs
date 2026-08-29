use sha3::{Digest, Sha3_512};

use crate::foundation::{FOUNDATION_PROFILE, Hash512};

use super::{
    direct_mpc_participant_cursor::{
        DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH, DirectMpcCursorError,
        DirectMpcCursorRefusalCode, DirectMpcCursorResourceModel, DirectMpcJoinedSubsetMaster,
        DirectMpcParticipantCursor, DirectMpcPrssContext, ordinary_basis_weight_for_test,
        zero_basis_weights_at_point_for_test,
    },
    direct_mpc_prime_field::DirectMpcPrimeFieldElement,
    replicated_random_sharing::ReplicatedRandomSharingSubset,
};

const PARTICIPANT_POSITION: u16 = 0;

#[test]
fn basis_weights_have_the_required_degree_three_and_zero_polynomial_roots() {
    let subset = ReplicatedRandomSharingSubset::from_excluded_positions(
        FOUNDATION_PROFILE.participant_count,
        &[1, 4, 8],
    )
    .unwrap();
    assert_eq!(
        ordinary_basis_weight_for_test(subset, DirectMpcPrimeFieldElement::ZERO).unwrap(),
        DirectMpcPrimeFieldElement::ONE
    );
    for excluded_position in subset.excluded_positions() {
        let excluded_point = DirectMpcPrimeFieldElement::from_u16(excluded_position + 1);
        assert_eq!(
            ordinary_basis_weight_for_test(subset, excluded_point).unwrap(),
            DirectMpcPrimeFieldElement::ZERO
        );
        assert!(
            zero_basis_weights_at_point_for_test(subset, excluded_point)
                .unwrap()
                .iter()
                .all(|value| *value == DirectMpcPrimeFieldElement::ZERO)
        );
    }
    assert!(
        zero_basis_weights_at_point_for_test(subset, DirectMpcPrimeFieldElement::ZERO)
            .unwrap()
            .iter()
            .all(|value| *value == DirectMpcPrimeFieldElement::ZERO)
    );
    let member_point = DirectMpcPrimeFieldElement::from_u16(1);
    let zero_weights = zero_basis_weights_at_point_for_test(subset, member_point).unwrap();
    assert_eq!(zero_weights.len(), 3);
    assert_eq!(zero_weights[1], zero_weights[0].multiply(member_point));
    assert_eq!(zero_weights[2], zero_weights[1].multiply(member_point));
}

#[test]
fn small_cursor_is_deterministic_and_restores_at_phase_boundaries() {
    let context = small_context();
    let baseline_masters = measurement_masters(context);
    let mut baseline = DirectMpcParticipantCursor::new(
        context,
        PARTICIPANT_POSITION,
        &baseline_masters,
        checkpoint_key(),
    )
    .unwrap();
    let total_stream_count = DirectMpcCursorResourceModel::derive(context, PARTICIPANT_POSITION)
        .unwrap()
        .total_stream_count;
    let mut checkpoints = Vec::new();
    while !baseline.is_finished().unwrap() {
        baseline.step(&baseline_masters).unwrap();
        if matches!(baseline.next_stream_index(), 1 | 84 | 85 | 335) {
            checkpoints.push((
                baseline.next_stream_index(),
                baseline.checkpoint_bytes().unwrap(),
            ));
        }
    }
    assert_eq!(baseline.next_stream_index(), total_stream_count);
    let baseline_result = baseline.result_bytes().unwrap();

    for (captured_stream_index, checkpoint) in checkpoints {
        let restored_masters = measurement_masters(context);
        let mut restored = DirectMpcParticipantCursor::restore_from_checkpoint(
            context,
            PARTICIPANT_POSITION,
            &restored_masters,
            checkpoint_key(),
            &checkpoint,
        )
        .unwrap();
        assert_eq!(restored.next_stream_index(), captured_stream_index);
        while !restored.is_finished().unwrap() {
            restored.step(&restored_masters).unwrap();
        }
        assert_eq!(
            restored.result_bytes().unwrap().as_slice(),
            baseline_result.as_slice()
        );
    }
}

#[test]
fn checkpoint_mutation_wrong_key_context_and_source_order_are_refused() {
    let context = small_context();
    let masters = measurement_masters(context);
    let mut cursor =
        DirectMpcParticipantCursor::new(context, PARTICIPANT_POSITION, &masters, checkpoint_key())
            .unwrap();
    cursor.step(&masters).unwrap();
    let checkpoint = cursor.checkpoint_bytes().unwrap();

    let mut changed_body = checkpoint.to_vec();
    let changed_body_position = changed_body.len() / 2;
    changed_body[changed_body_position] ^= 0x80;
    let body_error = DirectMpcParticipantCursor::restore_from_checkpoint(
        context,
        PARTICIPANT_POSITION,
        &measurement_masters(context),
        checkpoint_key(),
        &changed_body,
    )
    .unwrap_err();
    assert_eq!(
        body_error.refusal_code(),
        DirectMpcCursorRefusalCode::CheckpointAuthentication
    );

    let mut changed_tag = checkpoint.to_vec();
    let final_position = changed_tag.len() - 1;
    changed_tag[final_position] ^= 0x01;
    let tag_error = DirectMpcParticipantCursor::restore_from_checkpoint(
        context,
        PARTICIPANT_POSITION,
        &measurement_masters(context),
        checkpoint_key(),
        &changed_tag,
    )
    .unwrap_err();
    assert_eq!(
        tag_error.refusal_code(),
        DirectMpcCursorRefusalCode::CheckpointAuthentication
    );

    let wrong_key_error = DirectMpcParticipantCursor::restore_from_checkpoint(
        context,
        PARTICIPANT_POSITION,
        &measurement_masters(context),
        [0xa5; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH],
        &checkpoint,
    )
    .unwrap_err();
    assert_eq!(
        wrong_key_error.refusal_code(),
        DirectMpcCursorRefusalCode::CheckpointAuthentication
    );

    let alternate_context = DirectMpcPrssContext::new(
        Hash512::from_bytes([0xff; 64]),
        context.preparation_context_identity(),
        context.seed_terminal_identity(),
        context.participant_count(),
        context.ordinary_field_count(),
        context.zero_field_count(),
    );
    let context_error = DirectMpcParticipantCursor::restore_from_checkpoint(
        alternate_context,
        PARTICIPANT_POSITION,
        &measurement_masters(alternate_context),
        checkpoint_key(),
        &checkpoint,
    )
    .unwrap_err();
    assert!(matches!(
        context_error,
        DirectMpcCursorError::CheckpointMismatch {
            field: "candidate identity"
        }
    ));

    let mut wrong_order = measurement_masters(context);
    wrong_order.swap(0, 1);
    let source_error = DirectMpcParticipantCursor::restore_from_checkpoint(
        context,
        PARTICIPANT_POSITION,
        &wrong_order,
        checkpoint_key(),
        &checkpoint,
    )
    .unwrap_err();
    assert_eq!(
        source_error.refusal_code(),
        DirectMpcCursorRefusalCode::SourceGeometry
    );
}

#[test]
fn cursor_refuses_preboundary_checkpoint_preresult_and_postfinish_work() {
    let context = small_context();
    let masters = measurement_masters(context);
    let mut cursor =
        DirectMpcParticipantCursor::new(context, PARTICIPANT_POSITION, &masters, checkpoint_key())
            .unwrap();
    assert_eq!(
        cursor.checkpoint_bytes().unwrap_err(),
        DirectMpcCursorError::CheckpointUnavailable
    );
    assert_eq!(
        cursor.result_bytes().unwrap_err(),
        DirectMpcCursorError::ResultUnavailable
    );
    while !cursor.is_finished().unwrap() {
        cursor.step(&masters).unwrap();
    }
    assert_eq!(
        cursor.step(&masters).unwrap_err(),
        DirectMpcCursorError::CursorFinished
    );
}

#[test]
fn completion_resource_model_matches_the_committed_candidate_geometry() {
    let context = DirectMpcPrssContext::new(
        Hash512::from_bytes([0x11; 64]),
        Hash512::from_bytes([0x22; 64]),
        Hash512::from_bytes([0x33; 64]),
        FOUNDATION_PROFILE.participant_count,
        30_175,
        9_925,
    );
    let resource = DirectMpcCursorResourceModel::derive(context, PARTICIPANT_POSITION).unwrap();

    assert_eq!(resource.authorized_subset_count_per_participant, 84);
    assert_eq!(resource.ordinary_stream_count, 84);
    assert_eq!(resource.zero_basis_stream_count, 252);
    assert_eq!(resource.total_stream_count, 336);
    assert_eq!(resource.ordinary_field_count, 30_175);
    assert_eq!(resource.zero_field_count, 9_925);
    assert_eq!(resource.field_output_count, 5_035_800);
    assert_eq!(resource.source_byte_length, 161_145_600);
    assert_eq!(
        resource.basis_precomputation_field_multiplication_count,
        756
    );
    assert_eq!(resource.ordinary_basis_modular_inverse_count, 84);
    assert_eq!(resource.weight_field_multiplication_count, 5_035_800);
    assert_eq!(resource.accumulation_field_addition_count, 4_995_700);
    assert_eq!(resource.maximum_xof_output_allocation_byte_length, 965_600);
    assert_eq!(resource.canonical_accumulator_byte_length, 120_300);
    assert_eq!(resource.internal_accumulator_byte_length, 160_400);
    assert_eq!(resource.checkpoint_byte_length, 120_753);
    assert_eq!(resource.cumulative_checkpoint_byte_length, 40_573_008);
    assert_eq!(resource.result_byte_length, 120_639);
    assert!(
        resource.maximum_xof_output_allocation_byte_length
            <= FOUNDATION_PROFILE.maximum_copied_buffer_byte_length as u64
    );
}

fn small_context() -> DirectMpcPrssContext {
    DirectMpcPrssContext::new(
        Hash512::from_bytes([0x11; 64]),
        Hash512::from_bytes([0x22; 64]),
        Hash512::from_bytes([0x33; 64]),
        FOUNDATION_PROFILE.participant_count,
        17,
        11,
    )
}

fn measurement_masters(context: DirectMpcPrssContext) -> Vec<DirectMpcJoinedSubsetMaster> {
    ReplicatedRandomSharingSubset::iter(context.participant_count())
        .unwrap()
        .filter(|subset| subset.contains(PARTICIPANT_POSITION).unwrap())
        .map(|subset| {
            let mut derivation = Sha3_512::new();
            derivation.update(b"sealed-lattice/v1/test/direct-mpc-subset-master");
            derivation.update(context.candidate_identity().as_bytes());
            derivation.update(context.preparation_context_identity().as_bytes());
            derivation.update(context.seed_terminal_identity().as_bytes());
            derivation.update(subset.excluded_position_mask().to_le_bytes());
            let digest = derivation.finalize();
            let bytes = core::array::from_fn(|position| digest[position]);
            DirectMpcJoinedSubsetMaster::new(subset, bytes)
        })
        .collect()
}

fn checkpoint_key() -> [u8; DIRECT_MPC_CURSOR_CHECKPOINT_KEY_BYTE_LENGTH] {
    core::array::from_fn(|position| 0x91_u8.wrapping_add((position as u8).wrapping_mul(13)))
}
