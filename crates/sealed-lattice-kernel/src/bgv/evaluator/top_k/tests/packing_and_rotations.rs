use super::*;
use std::collections::BTreeSet;

#[test]
fn packed_score_slots_follow_generator_order_without_collisions() {
    let ring_order = 2 * POLYNOMIAL_DEGREE;
    let slot_elements = (0..POLYNOMIAL_DEGREE)
        .map(|logical_slot_index| {
            logical_slot_galois_element(logical_slot_index).expect("logical slot Galois element")
        })
        .collect::<Vec<_>>();

    assert_eq!(slot_elements[0], 1);
    assert_eq!(slot_elements[1], 3);
    assert_eq!(slot_elements[2], 9);
    assert_eq!(slot_elements[GENERATOR_SUBGROUP_ORDER], ring_order - 1);
    assert_eq!(slot_elements.iter().copied().collect::<BTreeSet<_>>().len(), POLYNOMIAL_DEGREE);
    assert!(slot_elements.iter().all(|element| element % 2 == 1));
    assert!(
        slot_elements[..GENERATOR_SUBGROUP_ORDER]
            .windows(2)
            .all(|adjacent_slots| {
                adjacent_slots[1] == adjacent_slots[0] * 3 % ring_order
            })
    );
}

#[test]
fn direct_score_packing_rotations_move_score_slots_to_packed_slots() {
    let rotations = direct_score_packing_galois_elements(20).expect("direct score rotations");

    assert_eq!(rotations.len(), 1);
    assert!(rotations.iter().all(|rotation| rotation % 2 == 1));
    for option in 0..20 {
        let source_slot = option;
        for target_logical_index in [option, option + 20] {
            let target_slot = target_logical_index;
            let galois_element = galois_element_moving_slot_to_target(source_slot, target_slot)
                .expect("slot move Galois element");
            let source_exponent =
                logical_slot_galois_element(source_slot).expect("source slot element");
            let target_exponent =
                logical_slot_galois_element(target_slot).expect("target slot element");
            let source_for_target = (galois_element * target_exponent) % (2 * POLYNOMIAL_DEGREE);

            assert_eq!(source_for_target, source_exponent);
            if source_slot == target_slot {
                assert_eq!(galois_element, 1);
            } else {
                assert!(rotations.contains(&galois_element));
            }
        }
    }
}

#[test]
fn direct_score_packing_duplicates_the_canonical_option_window() {
    let context = EvaluatorContext::new("logical-score-packing", 2).expect("context");
    let option_values = (1_u64..=20).collect::<Vec<_>>();
    let encrypted_scores = context
        .key()
        .encrypt_slots(&option_values, "logical-score-packing-input")
        .expect("encrypt scores");
    let packed_scores = pack_direct_score_slots(
        &context,
        &encrypted_scores,
        option_values.len(),
        "logical-score-packing",
    )
    .expect("pack scores");
    let decoded_slots = context
        .key()
        .decrypt_to_slots(&packed_scores)
        .expect("decrypt packed scores");
    let mut expected_slots = vec![0_u64; POLYNOMIAL_DEGREE];
    expected_slots[..option_values.len()].copy_from_slice(&option_values);
    expected_slots[option_values.len()..2 * option_values.len()].copy_from_slice(&option_values);

    assert_eq!(decoded_slots, expected_slots);
}

#[test]
fn compact_rotation_basis_covers_selected_logical_rotations() {
    let aggregate_basis =
        direct_score_packing_basis_galois_elements(20).expect("direct score basis");
    let forward_basis = packed_rank_forward_basis_galois_elements(20).expect("rank forward basis");
    let return_basis = packed_rank_return_basis_galois_elements(20).expect("rank return basis");
    let schedule = selected_evaluator_rotation_key_schedule(20).expect("schedule");
    let working_level_keys = schedule
        .iter()
        .filter(|(_, level)| *level == SELECTED_EVALUATOR_WORKING_LEVEL)
        .map(|(rotation, _)| *rotation)
        .collect::<std::collections::BTreeSet<_>>();

    // The power-of-two bases cover score shifts and pair-window offsets: the
    // largest window offset for twenty options is 189, so eight bits each.
    assert_eq!(aggregate_basis.len(), 2);
    assert_eq!(forward_basis.len(), 8);
    assert_eq!(return_basis.len(), 8);
    // Every schedule entry sits at the working level; lower-level uses are
    // served by truncation of the same keys.
    assert_eq!(schedule.len(), 16);
    assert_eq!(schedule.len(), working_level_keys.len());
    assert!(!working_level_keys.contains(&(2 * POLYNOMIAL_DEGREE - 1)));
    for rotation in forward_basis.iter().chain(return_basis.iter()) {
        assert!(working_level_keys.contains(rotation));
    }
    assert!(
        aggregate_basis
            .iter()
            .all(|rotation| return_basis.contains(rotation))
    );
    let composed_score_packing_rotation = aggregate_basis
        .iter()
        .fold(1_usize, |accumulated, rotation| {
            (accumulated * rotation) % (2 * POLYNOMIAL_DEGREE)
        });
    assert_eq!(
        direct_score_packing_galois_elements(20).expect("logical packing"),
        vec![composed_score_packing_rotation],
    );
}
