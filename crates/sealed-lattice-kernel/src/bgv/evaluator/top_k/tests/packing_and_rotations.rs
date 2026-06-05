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
    let schedule =
        selected_evaluator_rotation_key_schedule(20, DATA_PRIMES.len() - 1).expect("schedule");
    let full_level = DATA_PRIMES.len() - 1;
    let full_level_keys = schedule
        .iter()
        .filter(|(_, level)| *level == full_level)
        .map(|(rotation, _)| *rotation)
        .collect::<std::collections::BTreeSet<_>>();
    let return_level_keys = schedule
        .iter()
        .filter(|(_, level)| *level == DIRECT_COMPARISON_OUTPUT_LEVEL)
        .map(|(rotation, _)| *rotation)
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(aggregate_basis.len(), 15);
    assert_eq!(forward_basis.len(), 5);
    assert_eq!(return_basis.len(), 5);
    assert_eq!(schedule.len(), 20);
    assert_eq!(full_level_keys.len(), 15);
    assert_eq!(return_level_keys.len(), 5);
    assert!(full_level_keys.contains(&(2 * POLYNOMIAL_DEGREE - 1)));
    for rotation in direct_score_packing_galois_elements(20).expect("logical packing") {
        let (requires_conjugation, exponent) =
            generator_exponent_or_conjugated(rotation).expect("covered rotation");
        if requires_conjugation {
            assert!(full_level_keys.contains(&(2 * POLYNOMIAL_DEGREE - 1)));
        }
        for basis_rotation in generator_power_basis_for_exponent(exponent) {
            assert!(full_level_keys.contains(&basis_rotation));
        }
    }
}

#[test]
fn packed_rank_rotation_set_matches_unordered_pair_schedule() {
    let rotations = super::packed_rank_galois_elements(20).expect("rotations");
    let unique_rotations = rotations
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();

    assert_eq!(rotations.len(), 38);
    assert_eq!(unique_rotations.len(), 38);
    assert_eq!(rotations[0], 3);
    assert_eq!(
        rotations[1],
        super::inverse_galois_element(3).expect("inverse")
    );
    assert!(rotations.iter().all(|rotation| rotation % 2 == 1));
    assert!(
        rotations
            .iter()
            .all(|rotation| *rotation < 2 * POLYNOMIAL_DEGREE)
    );
}
