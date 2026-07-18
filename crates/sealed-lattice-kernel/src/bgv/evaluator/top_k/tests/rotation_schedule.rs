use std::collections::BTreeSet;

use super::*;

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
    assert_eq!(
        slot_elements.iter().copied().collect::<BTreeSet<_>>().len(),
        POLYNOMIAL_DEGREE
    );
    assert!(slot_elements.iter().all(|element| element % 2 == 1));
    assert!(
        slot_elements[..GENERATOR_SUBGROUP_ORDER]
            .windows(2)
            .all(|adjacent_slots| { adjacent_slots[1] == adjacent_slots[0] * 3 % ring_order })
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
        .collect::<BTreeSet<_>>();

    assert_eq!(aggregate_basis.len(), 2);
    assert_eq!(forward_basis.len(), 4);
    assert_eq!(return_basis.len(), 4);
    assert_eq!(schedule.len(), 4);
    assert_eq!(schedule.len(), working_level_keys.len());
    assert!(!working_level_keys.contains(&(2 * POLYNOMIAL_DEGREE - 1)));
    assert_eq!(
        working_level_keys,
        [3, 34_243, 37_611, 43_691].into_iter().collect()
    );
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

    let pair_window_offsets = [
        19, 37, 54, 70, 85, 99, 112, 124, 135, 145, 154, 162, 169, 175, 180, 184, 187, 189,
    ];
    let score_packing_hops = generator_inverse_power_basis_for_exponent(20)
        .expect("score-packing path")
        .len();
    let pair_shift_hops = (1..20)
        .map(|shift| {
            generator_power_basis_for_exponent(shift)
                .expect("pair-shift path")
                .len()
                * 2
        })
        .sum::<usize>();
    let window_hops = pair_window_offsets
        .into_iter()
        .map(|shift| {
            generator_inverse_power_basis_for_exponent(shift)
                .expect("window path")
                .len()
                * 2
        })
        .sum::<usize>();
    assert_eq!(score_packing_hops + pair_shift_hops + window_hops, 568);
    assert_eq!(
        (1..=189)
            .map(|shift| generator_power_basis_for_exponent(shift)
                .expect("path")
                .len())
            .max(),
        Some(18)
    );
}
