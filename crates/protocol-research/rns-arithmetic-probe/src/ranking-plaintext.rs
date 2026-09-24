use super::DEGREE;
use supported_profile::{PLAINTEXT_MODULUS as PRIME, Profile};

fn multiply(left: u32, right: u32) -> u32 {
    (u64::from(left) * u64::from(right) % u64::from(PRIME)) as u32
}
fn power(mut value: u32, mut exponent: u32) -> u32 {
    let mut result = 1;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, value);
        }
        value = multiply(value, value);
        exponent >>= 1;
    }
    result
}
fn centered(value: u32) -> i32 {
    if value > PRIME / 2 {
        value as i32 - PRIME as i32
    } else {
        value as i32
    }
}
fn interpolate(points: &[u32], values: &[u32]) -> Vec<u32> {
    let mut differences = values.to_vec();
    for order in 1..points.len() {
        for index in (order..points.len()).rev() {
            let numerator = (differences[index] + PRIME - differences[index - 1]) % PRIME;
            let denominator = (points[index] + PRIME - points[index - order]) % PRIME;
            assert_ne!(denominator, 0);
            differences[index] = multiply(numerator, power(denominator, PRIME - 2));
        }
    }
    let mut polynomial = vec![*differences.last().unwrap()];
    for index in (0..points.len() - 1).rev() {
        let mut next = vec![0; polynomial.len() + 1];
        for (degree, coefficient) in polynomial.into_iter().enumerate() {
            next[degree] = (next[degree] + PRIME - multiply(coefficient, points[index])) % PRIME;
            next[degree + 1] = (next[degree + 1] + coefficient) % PRIME;
        }
        next[0] = (next[0] + differences[index]) % PRIME;
        polynomial = next;
    }
    polynomial
}

pub(super) fn encode(slots: &[u32]) -> Vec<i32> {
    assert_eq!(slots.len(), DEGREE / 4);
    let length = DEGREE / 2;
    let mut natural = vec![0; length];
    let mut exponent = 1;
    for value in slots {
        natural[(exponent - 1) / 2] = *value;
        exponent = 5 * exponent % DEGREE;
    }
    let logarithm = length.ilog2();
    for index in 0..length {
        let reversed = index.reverse_bits() >> (usize::BITS - logarithm);
        if index < reversed {
            natural.swap(index, reversed);
        }
    }
    let inverse_root = power(9, PRIME - 2);
    let mut width = 2;
    while width <= length {
        let step = power(inverse_root, (length / width) as u32);
        for block in natural.chunks_exact_mut(width) {
            let (left, right) = block.split_at_mut(width / 2);
            let mut twiddle = 1;
            for (left, right) in left.iter_mut().zip(right) {
                let first = *left;
                let second = multiply(*right, twiddle);
                *left = (first + second) % PRIME;
                *right = (first + PRIME - second) % PRIME;
                twiddle = multiply(twiddle, step);
            }
        }
        width *= 2;
    }
    let mut coefficients = vec![0; DEGREE];
    let mut twist = power(length as u32, PRIME - 2);
    let inverse_twist = power(3, PRIME - 2);
    for (index, value) in natural.into_iter().enumerate() {
        coefficients[2 * index] = centered(multiply(value, twist));
        twist = multiply(twist, inverse_twist);
    }
    coefficients
}

/// The comparison polynomial's coefficients, each rank-equality power's
/// weights at the requested ranks' slots and the comparison input offset.
///
/// The comparison polynomial is one on every odd point of the profile's
/// comparison degree above zero and zero below it. Slot
/// `(option * options + rank) * window + opponent` compares the option with
/// the opponent, and the offset breaks ties toward the lower position.
pub fn parameters(profile: Profile, top_count: usize) -> (Vec<i32>, Vec<Vec<i32>>, Vec<i32>) {
    let options = profile.options();
    let window = profile.rank_window();
    assert!((1..=options).contains(&top_count));
    let maximum = profile.comparison_degree() as i32;
    let points: Vec<_> = (0..=maximum)
        .map(|index| (2 * index - maximum).rem_euclid(PRIME as i32) as u32)
        .collect();
    let values: Vec<_> = (0..=maximum)
        .map(|index| u32::from(2 * index > maximum))
        .collect();
    let comparison = interpolate(&points, &values);
    assert_eq!(comparison[0], power(2, PRIME - 2));
    assert!(
        comparison
            .iter()
            .enumerate()
            .all(|(index, value)| index == 0 || index % 2 == 1 || *value == 0)
    );
    let ranks: Vec<_> = (0..options as u32).collect();
    let equality: Vec<_> = (0..options as u32)
        .map(|requested| {
            interpolate(
                &ranks,
                &ranks
                    .iter()
                    .map(|rank| u32::from(*rank == requested))
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let ranking = (0..options)
        .map(|exponent| {
            let mut slots = vec![0; DEGREE / 4];
            for option in 0..options {
                for rank in 0..top_count {
                    slots[(option * options + rank) * window] = equality[rank][exponent];
                }
            }
            encode(&slots)
        })
        .collect();
    let mut offset = vec![PRIME - 1; DEGREE / 4];
    for option in 0..options {
        for rank in 0..options {
            for opponent in 0..option {
                offset[(option * options + rank) * window + opponent] = 1;
            }
        }
    }
    (
        comparison.into_iter().map(centered).collect(),
        ranking,
        encode(&offset),
    )
}

#[cfg(test)]
mod tests {
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
                        .all(
                            |polynomial| evaluate_subring(polynomial, power(point, PRIME - 2)) == 0
                        )
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
}
