use std::collections::BTreeSet;

use super::*;

fn compose_galois_path(path: &[usize]) -> usize {
    path.iter().fold(1_usize, |composed, galois_element| {
        composed * galois_element % (2 * POLYNOMIAL_DEGREE)
    })
}

fn apply_nonconjugating_galois_path_to_logical_slots(
    mut slots: Vec<u64>,
    path: &[usize],
) -> Vec<u64> {
    for galois_element in path {
        let (requires_conjugation, exponent) = generator_exponent_or_conjugated(*galois_element)
            .expect("selected Galois element has a logical-slot position");
        assert!(
            !requires_conjugation,
            "selected pair-window paths must not exchange the two logical-slot halves"
        );
        let mut rotated = vec![0_u64; POLYNOMIAL_DEGREE];
        for half_offset in [0, GENERATOR_SUBGROUP_ORDER] {
            for destination_offset in 0..GENERATOR_SUBGROUP_ORDER {
                let source_offset = (destination_offset + exponent) % GENERATOR_SUBGROUP_ORDER;
                rotated[half_offset + destination_offset] = slots[half_offset + source_offset];
            }
        }
        slots = rotated;
    }
    slots
}

#[test]
fn packed_slots_follow_generator_order_without_collisions() {
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
fn directed_paths_compose_to_every_selected_pair_offset_and_shift() {
    for window_offset in 0..190 {
        let path =
            forward_pair_window_rotation_path(window_offset).expect("forward pair-window path");
        assert_eq!(
            compose_galois_path(&path),
            galois_power(window_offset).expect("window-offset Galois power"),
            "forward path composition drifted at window offset {window_offset}"
        );
        let first_negative_step = path
            .iter()
            .position(|element| *element != POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT)
            .unwrap_or(path.len());
        let first_negative_one_step = path
            .iter()
            .position(|element| *element == NEGATIVE_ONE_GALOIS_ELEMENT)
            .unwrap_or(path.len());
        assert!(
            path[..first_negative_step]
                .iter()
                .all(|element| *element == POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT)
        );
        assert!(
            path[first_negative_step..first_negative_one_step]
                .iter()
                .all(|element| *element == NEGATIVE_SEVEN_GALOIS_ELEMENT)
        );
        assert!(
            path[first_negative_one_step..]
                .iter()
                .all(|element| *element == NEGATIVE_ONE_GALOIS_ELEMENT)
        );
    }

    for shift in 0..20 {
        let path = inverse_pair_shift_rotation_path(shift).expect("inverse pair-shift path");
        assert_eq!(
            compose_galois_path(&path),
            inverse_galois_element(galois_power(shift).expect("shift Galois power"))
                .expect("inverse shift Galois element"),
            "inverse path composition drifted at shift {shift}"
        );
        let first_negative_one_step = path
            .iter()
            .position(|element| *element == NEGATIVE_ONE_GALOIS_ELEMENT)
            .unwrap_or(path.len());
        assert!(
            path[..first_negative_one_step]
                .iter()
                .all(|element| *element == NEGATIVE_SEVEN_GALOIS_ELEMENT)
        );
        assert!(
            path[first_negative_one_step..]
                .iter()
                .all(|element| *element == NEGATIVE_ONE_GALOIS_ELEMENT)
        );
    }

    assert!(forward_pair_window_rotation_path(190).is_err());
    assert!(inverse_pair_shift_rotation_path(20).is_err());
}

#[test]
fn pre_rotation_window_selector_makes_the_post_rotation_mask_semantically_redundant() {
    let option_count = usize::from(FOUNDATION_PROFILE.option_count);
    let aggressive_slots = (0..POLYNOMIAL_DEGREE)
        .map(|slot_index| {
            PLAINTEXT_MODULUS - 1 - u64::try_from(slot_index).expect("slot index fits u64")
        })
        .collect::<Vec<_>>();
    let mut window_offset = 0_usize;

    for shift in 1..option_count {
        let window_size = option_count - shift;
        let window_end = window_offset + window_size;
        let rotation_path =
            forward_pair_window_rotation_path(window_offset).expect("forward pair-window path");

        let mut source_window_mask = vec![0_u64; POLYNOMIAL_DEGREE];
        source_window_mask[window_offset..window_end].fill(1);
        let rotated_source_window_mask =
            apply_nonconjugating_galois_path_to_logical_slots(source_window_mask, &rotation_path);
        let mut expected_lower_pair_mask = vec![0_u64; POLYNOMIAL_DEGREE];
        expected_lower_pair_mask[..window_size].fill(1);
        assert_eq!(
            rotated_source_window_mask, expected_lower_pair_mask,
            "source-window support did not map exactly to the lower-pair support for shift {shift}"
        );

        let mut selected_aggressive_slots = vec![0_u64; POLYNOMIAL_DEGREE];
        selected_aggressive_slots[window_offset..window_end]
            .copy_from_slice(&aggressive_slots[window_offset..window_end]);
        let without_post_rotation_mask = apply_nonconjugating_galois_path_to_logical_slots(
            selected_aggressive_slots,
            &rotation_path,
        );
        let with_post_rotation_mask = without_post_rotation_mask
            .iter()
            .zip(&expected_lower_pair_mask)
            .map(|(slot, mask)| slot * mask)
            .collect::<Vec<_>>();
        assert_eq!(
            without_post_rotation_mask, with_post_rotation_mask,
            "post-rotation mask changed a selected logical slot for shift {shift}"
        );
        assert_eq!(
            &without_post_rotation_mask[..window_size],
            &aggressive_slots[window_offset..window_end],
            "directed path changed source order for shift {shift}"
        );
        assert!(
            without_post_rotation_mask[window_size..]
                .iter()
                .all(|slot| *slot == 0),
            "directed path left selected support outside the lower-pair window for shift {shift}"
        );

        window_offset = window_end;
    }

    assert_eq!(window_offset, option_count * (option_count - 1) / 2);
}

#[test]
fn selected_directed_schedule_has_exact_elements_level_and_path_cost() {
    assert_eq!(
        (
            NEGATIVE_SEVEN_GALOIS_ELEMENT,
            NEGATIVE_ONE_GALOIS_ELEMENT,
            POSITIVE_THIRTY_EIGHT_GALOIS_ELEMENT,
        ),
        (7_971, 43_691, 130_393)
    );
    assert_eq!(
        selected_evaluator_rotation_key_schedule(20).expect("selected rotation schedule"),
        vec![
            (7_971, DIRECT_COMPARISON_OUTPUT_LEVEL),
            (43_691, DIRECT_COMPARISON_OUTPUT_LEVEL),
            (130_393, DIRECT_COMPARISON_OUTPUT_LEVEL),
        ]
    );
    assert!(selected_evaluator_rotation_key_schedule(19).is_err());
    assert!(selected_evaluator_rotation_key_schedule(21).is_err());

    let window_offsets = [
        0, 19, 37, 54, 70, 85, 99, 112, 124, 135, 145, 154, 162, 169, 175, 180, 184, 187, 189,
    ];
    let mut path_lengths = window_offsets
        .into_iter()
        .map(|window_offset| {
            forward_pair_window_rotation_path(window_offset)
                .expect("forward pair-window path")
                .len()
        })
        .chain((1..20).map(|shift| {
            inverse_pair_shift_rotation_path(shift)
                .expect("inverse pair-shift path")
                .len()
        }))
        .collect::<Vec<_>>();
    assert_eq!(path_lengths.iter().sum::<usize>(), 211);
    assert_eq!(path_lengths.iter().copied().max(), Some(11));
    path_lengths.sort_unstable();
    assert_eq!(path_lengths.first().copied(), Some(0));
}
