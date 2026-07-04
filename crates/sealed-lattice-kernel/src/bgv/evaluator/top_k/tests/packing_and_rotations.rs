use super::*;

#[test]
fn packed_score_slots_follow_generator_order_without_collisions() {
    let slots = (0..40).map(packed_score_slot).collect::<Vec<_>>();
    let unique_slots = slots
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(slots[0], 0);
    assert_eq!(slots[1], 1);
    assert_eq!(slots[2], 4);
    assert_eq!(unique_slots.len(), slots.len());
    assert!(slots.iter().all(|slot| *slot < POLYNOMIAL_DEGREE));
}

#[test]
fn direct_score_packing_rotations_move_score_slots_to_packed_slots() {
    let rotations = direct_score_packing_galois_elements(20).expect("direct score rotations");

    assert_eq!(rotations.len(), 37);
    assert!(rotations.iter().all(|rotation| rotation % 2 == 1));
    for option in 0..20 {
        let source_slot = option;
        for target_logical_index in [option, option + 20] {
            let target_slot = packed_score_slot(target_logical_index);
            let galois_element = galois_element_moving_slot_to_target(source_slot, target_slot)
                .expect("slot move Galois element");
            let source_for_target =
                (galois_element * (2 * target_slot + 1)) % (2 * POLYNOMIAL_DEGREE);

            assert_eq!(source_for_target, 2 * source_slot + 1);
            if source_slot == target_slot {
                assert_eq!(galois_element, 1);
            } else {
                assert!(rotations.contains(&galois_element));
            }
        }
    }
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
    assert_eq!(aggregate_basis.len(), 15);
    assert_eq!(forward_basis.len(), 8);
    assert_eq!(return_basis.len(), 8);
    // Every schedule entry sits at the working level; lower-level uses are
    // served by truncation of the same keys.
    assert_eq!(schedule.len(), working_level_keys.len());
    assert!(working_level_keys.contains(&(2 * POLYNOMIAL_DEGREE - 1)));
    for rotation in forward_basis.iter().chain(return_basis.iter()) {
        assert!(working_level_keys.contains(rotation));
    }
    for rotation in direct_score_packing_galois_elements(20).expect("logical packing") {
        let (requires_conjugation, exponent) =
            generator_exponent_or_conjugated(rotation).expect("covered rotation");
        if requires_conjugation {
            assert!(working_level_keys.contains(&(2 * POLYNOMIAL_DEGREE - 1)));
        }
        for basis_rotation in generator_power_basis_for_exponent(exponent) {
            assert!(working_level_keys.contains(&basis_rotation));
        }
    }
}
