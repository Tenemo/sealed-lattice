use super::*;

fn evaluate(coefficients: &[i32], point: u32) -> u32 {
    coefficients.iter().rev().fold(0, |sum, coefficient| {
        (multiply(sum, point) + coefficient.rem_euclid(PRIME as i32) as u32) % PRIME
    })
}

fn evaluate_subring(coefficients: &[i32], point: u32) -> u32 {
    assert!(
        coefficients
            .iter()
            .enumerate()
            .all(|(index, value)| index % 2 == 0 || *value == 0)
    );
    // Slots evaluate Y = X^2. The base field has roots for the plaintext
    // subring, not for the complete ciphertext ring.
    coefficients
        .iter()
        .step_by(2)
        .rev()
        .fold(0, |sum, coefficient| {
            (multiply(sum, point) + coefficient.rem_euclid(PRIME as i32) as u32) % PRIME
        })
}

fn slot_point(slot: usize) -> u32 {
    let exponent = (0..slot).fold(1usize, |value, _| 5 * value % DEGREE);
    power(3, exponent as u32)
}

// Every boundary shape: the fewest and most participants and options,
// and the completion profile.
fn profiles() -> Vec<Profile> {
    [(3, 2), (3, 20), (10, 10), (20, 2), (20, 20)]
        .into_iter()
        .map(|(participants, options)| Profile::new(participants, options).unwrap())
        .collect()
}

#[test]
fn comparison_and_encoded_rank_coefficients_match_direct_evaluation() {
    for profile in profiles() {
        let options = profile.options();
        let window = profile.rank_window();
        let active = options * options * window;
        let (comparison, ranking, offset) = parameters(profile, options);
        let maximum = profile.comparison_degree() as i32;
        for difference in (-maximum..=maximum).step_by(2) {
            assert_eq!(
                evaluate(&comparison, difference.rem_euclid(PRIME as i32) as u32),
                u32::from(difference > 0)
            );
        }
        for slot in [
            0,
            1,
            window,
            active - window,
            active - 1,
            active,
            DEGREE / 4 - 1,
        ] {
            let point = slot_point(slot);
            let first = slot < active && slot.is_multiple_of(window);
            let requested = (slot / window) % options;
            let coefficients: Vec<_> = ranking
                .iter()
                .map(|polynomial| evaluate_subring(polynomial, point) as i32)
                .collect();
            for rank in 0..options {
                assert_eq!(
                    evaluate(&coefficients, rank as u32),
                    u32::from(first && rank == requested)
                );
            }
            let option = slot / (options * window);
            let expected_offset = if slot < active && slot % window < option {
                1
            } else {
                PRIME - 1
            };
            assert_eq!(evaluate_subring(&offset, point), expected_offset);
            assert!(
                ranking
                    .iter()
                    .all(|polynomial| evaluate_subring(polynomial, power(point, PRIME - 2)) == 0)
            );
        }
    }
}

#[test]
fn requested_rank_coefficients_zero_every_omitted_output_in_the_same_subring() {
    for profile in profiles() {
        let options = profile.options();
        let window = profile.rank_window();
        let active = options * options * window;
        let mut top_counts = vec![1, options - 1, options];
        top_counts.dedup();
        for top_count in top_counts {
            let (_, ranking, _) = parameters(profile, top_count);
            for polynomial in &ranking {
                assert!(polynomial.iter().enumerate().all(|(index, value)| {
                    value.unsigned_abs() <= PRIME / 2 && (index % 2 == 0 || *value == 0)
                }));
            }
            let mut slots = vec![1, active - 1, active, DEGREE / 4 - 1];
            for option in [0, options / 2, options - 1] {
                for rank in [0, top_count - 1, top_count.min(options - 1), options - 1] {
                    slots.push((option * options + rank) * window);
                }
            }
            slots.sort_unstable();
            slots.dedup();
            for slot in slots {
                let point = slot_point(slot);
                let requested = slot / window % options;
                let selected =
                    slot < active && slot.is_multiple_of(window) && requested < top_count;
                let coefficients: Vec<_> = ranking
                    .iter()
                    .map(|polynomial| evaluate_subring(polynomial, point) as i32)
                    .collect();
                for rank in 0..options {
                    assert_eq!(
                        evaluate(&coefficients, rank as u32),
                        u32::from(selected && rank == requested),
                        "profile={profile:?}, top_count={top_count}, slot={slot}, rank={rank}"
                    );
                }
                assert!(ranking.iter().all(|polynomial| {
                    evaluate_subring(polynomial, power(point, PRIME - 2)) == 0
                }));
            }
        }
    }
}
